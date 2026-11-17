package workspace

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Gate A (SPO-Xmulti-OUT-016). Whenever the stored name of a selected owner is
// a name the workspace already holds (an artefact of any kind under it), the
// import never deletes anything of the workspace, so the owner that results is
// the existing artefacts together with the incoming ones (the incoming one
// wins only with --overwrite; without it an exact clash is the conflict
// refusal and this check is not reached). That result is checked as a whole by
// this one function, with or without --overwrite, and the owner is stored only
// if it is provably one coherent owner. Anything this function cannot show
// counts as not belonging: a key kept encrypted, a hardware signing file
// without a readable verification key, a key pair whose halves come from both
// sides and cannot be matched, an artefact of an unclassified kind.

// sideFlag says where an artefact of the result comes from.
type sideFlag uint8

const (
	onlyEx    sideFlag = 1 // the workspace holds it and the import does not replace it
	onlyInc   sideFlag = 2 // the import brings it (and replaces the workspace's, if any)
	bothSides sideFlag = 3 // the workspace holds it and the import brings the same content
)

type resArtefact struct {
	ref  ports.Ref
	side sideFlag
	data []byte        // content of a non-secret artefact; the incoming one when it replaces
	sec  *ports.Secret // the incoming secret, when it is one
	id   []byte
	done bool
}

type slotKey struct {
	name string
	vk   ports.Kind
	num  int
}

// keyKinds maps every verification key, signing key and hardware signing file
// kind to the verification key kind of its pair, and says which half it is.
var (
	vkOfKind = map[ports.Kind]ports.Kind{}
	roleOf   = map[ports.Kind]int{} // 0 verification key, 1 signing key, 2 hardware file
	hwKinds  = map[ports.Kind]bool{}
)

func init() {
	hw := map[ports.Kind]ports.Kind{
		ports.NodeVKey: ports.NodeHwsFile, ports.AddrVKey: ports.AddrHwsFile, ports.StakingVKey: ports.StakingHwsFile,
		ports.DRepVKey: ports.DRepHwsFile, ports.CCColdVKey: ports.CCColdHwsFile, ports.CCHotVKey: ports.CCHotHwsFile,
		ports.PolicyVKey: ports.PolicyHwsFile, ports.VotingVKey: ports.VotingHwsFile, ports.CalidusVKey: ports.CalidusHwsFile,
	}
	for sk, role := range ports.SigningKeyKinds() {
		vkOfKind[role.VKey], roleOf[role.VKey] = role.VKey, 0
		vkOfKind[sk], roleOf[sk] = role.VKey, 1
		if h, ok := hw[role.VKey]; ok {
			vkOfKind[h], roleOf[h], hwKinds[h] = role.VKey, 2, true
		}
	}
}

func rawOf(b []byte) []byte {
	env, err := pool.ParseEnvelope(b)
	if err != nil {
		return nil
	}
	k, err := env.Key32()
	if err != nil {
		return nil
	}
	return k
}

// hwsPubKey is the verification key a hardware signing file stores
// (`cborXPubKeyHex`, a 64-byte extended public key: the first 32 bytes).
func hwsPubKey(b []byte) []byte {
	var f struct {
		X string `json:"cborXPubKeyHex"`
	}
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	raw, err := hex.DecodeString(f.X)
	if err != nil || len(raw) != 66 || raw[0] != 0x58 || raw[1] != 0x40 {
		return nil
	}
	return raw[2:34]
}

func counterCold(b []byte) []byte {
	if c, err := pool.ParseIssueCounter(b); err == nil {
		return c.ColdVKey[:]
	}
	return nil
}

// certNames reports whether the certificate envelope b carries the 28-byte
// hash h (the credential or pool id the certificate is about).
func certNames(b []byte, h txbuild.KeyHash) bool {
	env, err := pool.ParseEnvelope(b)
	if err != nil {
		return false
	}
	raw, err := hex.DecodeString(env.CborHex)
	return err == nil && bytes.Contains(raw, h[:])
}

// certOperator is the pool id (the operator key hash) a pool registration or
// retirement certificate is about: the 28-byte string right after the
// certificate type, [3, <operator>, ...] or [4, <operator>, <epoch>]. nil when
// the envelope is not such a certificate.
func certOperator(b []byte) []byte {
	env, err := pool.ParseEnvelope(b)
	if err != nil {
		return nil
	}
	raw, err := hex.DecodeString(env.CborHex)
	if err != nil || len(raw) < 32 || raw[0]&0xe0 != 0x80 || (raw[1] != 3 && raw[1] != 4) || raw[2] != 0x58 || raw[3] != 0x1c {
		return nil
	}
	return raw[4:32]
}

type coherence struct {
	u       ImportWorkspace
	ctx     context.Context
	ws      *wsSnapshot
	o       *wsOwner
	final   string
	res     map[ports.Ref]*resArtefact
	destroy []*ports.Secret
	reasons []string
}

func (c *coherence) release() {
	for _, s := range c.destroy {
		s.Destroy()
	}
}

func (c *coherence) bad(r ports.Ref, why string) {
	c.reasons = append(c.reasons, fmt.Sprintf("%s (%s)", r.String(), why))
}

func (c *coherence) derive(sec *ports.Secret) []byte {
	if c.u.Deriver == nil || sec == nil {
		return nil
	}
	raw, err := c.u.Deriver.DeriveVerificationKey(c.ctx, sec)
	if err != nil {
		return nil
	}
	return raw
}

func (c *coherence) openExisting(r ports.Ref) *ports.Secret {
	v, ok := c.u.Dest.(ports.Vault)
	if !ok || !c.o.refs[r] {
		return nil
	}
	buf, err := v.Open(c.ctx, r)
	if err != nil {
		return nil
	}
	c.destroy = append(c.destroy, buf)
	return buf
}

func (c *coherence) sameSecret(r ports.Ref, inc *ports.Secret) bool {
	ex := c.openExisting(r)
	if ex == nil || inc == nil {
		return false
	}
	eq := false
	_ = ex.Use(func(a []byte) error {
		return inc.Use(func(b []byte) error { eq = bytes.Equal(a, b); return nil })
	})
	return eq
}

// identity is the 32-byte verification key an artefact of a key pair stands
// for, nil when it cannot be told.
func (c *coherence) identity(a *resArtefact) []byte {
	if a.done {
		return a.id
	}
	a.done = true
	switch roleOf[a.ref.Kind] {
	case 0:
		a.id = rawOf(a.data)
	case 1:
		switch {
		case a.sec != nil:
			a.id = c.derive(a.sec)
		case a.side == onlyEx:
			a.id = c.derive(c.openExisting(a.ref))
		}
	case 2:
		a.id = hwsPubKey(a.data)
	}
	return a.id
}

// slotView is what the artefacts of one key pair say about the key of the
// result.
type slotView struct {
	key  slotKey
	arts []*resArtefact
	id   []byte // the verification key of the result, nil when it cannot be told
	side sideFlag
}

func (c *coherence) view(key slotKey, arts []*resArtefact) *slotView {
	sort.Slice(arts, func(i, j int) bool {
		if ri, rj := roleOf[arts[i].ref.Kind], roleOf[arts[j].ref.Kind]; ri != rj {
			return ri < rj
		}
		return arts[i].ref.String() < arts[j].ref.String()
	})
	var incID, exID []byte
	hasEx, hasInc := false, false
	for _, a := range arts {
		hasEx, hasInc = hasEx || a.side == onlyEx, hasInc || a.side == onlyInc
		id := c.identity(a)
		if id == nil {
			continue
		}
		if a.side&onlyInc != 0 && incID == nil {
			incID = id
		}
		if (a.side == onlyEx || a.side == bothSides) && exID == nil {
			exID = id
		}
	}
	v := &slotView{key: key, arts: arts}
	switch {
	case incID != nil:
		v.id = incID
		v.side = onlyInc
		if exID != nil && bytes.Equal(exID, incID) {
			v.side = bothSides
		}
	case exID != nil:
		v.id, v.side = exID, onlyEx
	default:
		switch {
		case hasInc:
			v.side = onlyInc
		case hasEx:
			v.side = onlyEx
		default:
			v.side = bothSides
		}
	}
	return v
}

// checkCoherence returns "" when the owner that results from storing plan into
// the workspace's owner `final` is provably one coherent owner, and the reason
// it is not otherwise. note says what the merge adds.
//
// spec: SPO-Xmulti-OUT-014, SPO-Xmulti-OUT-016, SPO-Xmulti-OUT-018, SPO-Xmulti-OUT-019, SPO-Xmulti-INV-006
func (u ImportWorkspace) checkCoherence(ctx context.Context, ws *wsSnapshot, final string, plan []planned) (why, note string) {
	o := ws.owner(final)
	if o == nil {
		return "", ""
	}
	c := &coherence{u: u, ctx: ctx, ws: ws, o: o, final: final, res: map[ports.Ref]*resArtefact{}}
	defer c.release()

	var dsts []ports.Ref
	for _, p := range plan {
		dsts = append(dsts, p.dst)
	}
	exKind, incKind := o.kind(), kindOfRefs(dsts)
	if (exKind == KindPool && incKind == KindWallet) || (exKind == KindWallet && incKind == KindPool) {
		return fmt.Sprintf("it is a %s and the workspace owner %q is a %s; an owner is never merged into an owner of the other kind: import it under a new name (--rename)", incKind, final, exKind), ""
	}

	for r := range o.refs {
		a := &resArtefact{ref: r, side: onlyEx}
		if !r.Kind.Secret() {
			a.data, _ = ws.get(r)
		}
		c.res[r] = a
	}
	for _, p := range plan {
		a := c.res[p.dst]
		if a == nil {
			c.res[p.dst] = &resArtefact{ref: p.dst, side: onlyInc, data: p.data, sec: p.sec}
			continue
		}
		same := false
		if p.sec == nil {
			same = a.data != nil && bytes.Equal(a.data, p.data)
		} else {
			same = c.sameSecret(p.dst, p.sec)
		}
		a.data, a.sec, a.side = p.data, p.sec, onlyInc
		if same {
			a.side = bothSides
		}
	}

	refs := make([]ports.Ref, 0, len(c.res))
	for r := range c.res {
		refs = append(refs, r)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })

	// Key pairs: every half names the key of the result.
	groups := map[slotKey][]*resArtefact{}
	for _, r := range refs {
		if vk, ok := vkOfKind[r.Kind]; ok {
			k := slotKey{r.Name, vk, r.Num}
			groups[k] = append(groups[k], c.res[r])
		}
	}
	views := map[slotKey]*slotView{}
	var keys []slotKey
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		if keys[i].vk != keys[j].vk {
			return keys[i].vk < keys[j].vk
		}
		return keys[i].num < keys[j].num
	})
	for _, k := range keys {
		v := c.view(k, groups[k])
		views[k] = v
		hasEx, hasInc := false, false
		for _, a := range v.arts {
			hasEx, hasInc = hasEx || a.side == onlyEx, hasInc || a.side == onlyInc
		}
		mixed := hasEx && hasInc
		for _, a := range v.arts {
			id := c.identity(a)
			switch {
			case id != nil:
				if !bytes.Equal(id, v.id) {
					c.bad(a.ref, "it does not belong with the key pair of the result: its verification key differs from the one the other artefacts of the pair give")
				}
			case a.side == bothSides:
			case hwKinds[a.ref.Kind]:
				c.bad(a.ref, "the hardware signing file stores no verification key to check it with")
			case mixed:
				c.bad(a.ref, "its pair cannot be checked: one half comes from the workspace and one from the import")
			}
		}
	}

	anchor := func(name string, vk ports.Kind) *slotView { return views[slotKey{name, vk, 0}] }
	stake := anchor(final, ports.StakingVKey)
	cold := anchor(final, ports.NodeVKey)

	// A payment key and a stake key belong together only when they came together
	// (both from the workspace, or both from the import), are the same key on both
	// sides, or a base address of the result ties them.
	baseAddrTies := func(addrName string, pay, st *slotView) bool {
		a := c.res[ports.Ref{Name: addrName, Kind: ports.AddrFile}]
		if a == nil || a.data == nil || pay.id == nil || st.id == nil || u.Addresses == nil {
			return false
		}
		info, err := u.Addresses.InspectAddress(chain.Address(strings.TrimSpace(string(a.data))))
		if err != nil || info.PaymentKeyHash == nil || info.StakeKeyHash == nil {
			return false
		}
		return *info.PaymentKeyHash == txbuild.HashKey(pay.id) && *info.StakeKeyHash == txbuild.HashKey(st.id)
	}
	separate := func(x, y *slotView, why string) {
		if x.side == bothSides || y.side == bothSides || x.side == y.side {
			return
		}
		ex := x
		if y.side == onlyEx {
			ex = y
		}
		for _, a := range ex.arts {
			c.bad(a.ref, why)
		}
	}
	pay := anchor(final+".payment", ports.AddrVKey)
	keyAddr := anchor(final, ports.AddrVKey)
	for _, pa := range []*slotView{pay, keyAddr} {
		if pa == nil || stake == nil {
			continue
		}
		if pa.side == bothSides || stake.side == bothSides || pa.side == stake.side || baseAddrTies(pa.key.name, pa, stake) {
			continue
		}
		separate(pa, stake, "the stake keys and the payment keys of the result come from different owners (the workspace's and the import's) and no base address of the result ties them")
	}
	if pay != nil && keyAddr != nil {
		separate(pay, keyAddr, "the payment keys of the result come from different owners and are not shown to belong together")
	}

	coldID := func() []byte {
		if cold != nil && cold.id != nil {
			return cold.id
		}
		var out []byte
		for _, r := range refs {
			if r.Kind == ports.NodeCounter && c.res[r].data != nil {
				if k := counterCold(c.res[r].data); k != nil && (out == nil || c.res[r].side&onlyInc != 0) {
					out = k
				}
			}
		}
		return out
	}()
	stakeKey := func() []byte {
		if stake != nil {
			return stake.id
		}
		return nil
	}()

	inspect := func(a *resArtefact) (ports.AddressInfo, bool) {
		if a.data == nil || u.Addresses == nil {
			return ports.AddressInfo{}, false
		}
		info, err := u.Addresses.InspectAddress(chain.Address(strings.TrimSpace(string(a.data))))
		return info, err == nil
	}
	hashIs := func(h *txbuild.KeyHash, k []byte) bool { return h != nil && k != nil && *h == txbuild.HashKey(k) }

	maxKes, kesVK := -1, map[int][]byte{}
	for _, r := range refs {
		if r.Kind == ports.KesVKey || r.Kind == ports.KesSKey {
			if r.Num > maxKes {
				maxKes = r.Num
			}
		}
		if r.Kind == ports.KesVKey {
			kesVK[r.Num] = rawOf(c.res[r].data)
		}
	}

	open := ownerData{open: map[ports.Ref][]byte{}, skey: map[ports.Ref]*ports.Secret{}}
	for _, r := range refs {
		if a := c.res[r]; a.data != nil {
			open.open[r] = a.data
		}
	}

	for _, r := range refs {
		a := c.res[r]
		if _, isKey := vkOfKind[r.Kind]; isKey {
			continue
		}
		both := a.side == bothSides
		switch r.Kind {
		case ports.UpstreamEncryptedSKey:
			if !both {
				c.bad(r, "a key kept in upstream's encrypted form cannot be checked")
			}
		case ports.AddrFile:
			if both {
				continue
			}
			var k []byte
			if v := anchor(r.Name, ports.AddrVKey); v != nil {
				k = v.id
			}
			info, ok := inspect(a)
			switch {
			case !ok:
				c.bad(r, "the address cannot be checked")
			case !hashIs(info.PaymentKeyHash, k) || (info.StakeKeyHash != nil && !hashIs(info.StakeKeyHash, stakeKey)):
				c.bad(r, "the address cannot be derived from the keys of the result")
			}
		case ports.StakingAddr:
			if both {
				continue
			}
			if info, ok := inspect(a); !ok || !hashIs(info.StakeKeyHash, stakeKey) {
				c.bad(r, "the stake address cannot be derived from the stake key of the result")
			}
		case ports.StakingCert, ports.DelegCert, ports.VoteDelegCert, ports.StakingDeregCert:
			if !both && (stakeKey == nil || !certNames(a.data, txbuild.HashKey(stakeKey))) {
				c.bad(r, "the certificate cannot be shown to name the stake key of the result")
			}
		case ports.PoolCert, ports.PoolDeregCert:
			if !both {
				if op := certOperator(a.data); coldID == nil || op == nil || !bytes.Equal(op, poolIDOf(coldID)) {
					c.bad(r, "the certificate cannot be shown to be about the pool id of the cold key of the result")
				}
			}
		case ports.PoolIDFile:
			if !both {
				if coldID == nil || strings.TrimSpace(string(a.data)) != hex.EncodeToString(func() []byte { h := txbuild.HashKey(coldID); return h[:] }()) {
					c.bad(r, "the pool id is not the one of the cold key of the result")
				}
			}
		case ports.NodeCounter:
			if k := counterCold(a.data); k == nil || coldID == nil || !bytes.Equal(k, coldID) {
				c.bad(r, "the issue counter does not belong to the cold key of the result")
			}
		case ports.OpCert:
			oc, err := pool.ParseOpCert(a.data)
			switch {
			case err != nil:
				c.bad(r, "the operational certificate cannot be read")
			case coldID == nil:
				c.bad(r, "there is no cold key of the result to check the operational certificate against")
			case !bytes.Equal(oc.ColdVKey[:], coldID):
				c.bad(r, "the operational certificate names another cold key than the result's")
			case kesVK[r.Num] == nil:
				c.bad(r, fmt.Sprintf("there is no KES verification key %d to check the operational certificate against", r.Num))
			case !bytes.Equal(oc.KesVKey[:], kesVK[r.Num]):
				c.bad(r, fmt.Sprintf("the operational certificate names another hot key than the KES verification key %d of the result", r.Num))
			}
		case ports.KesCounter, ports.KesCounterNext:
			// checked below, together
		case ports.PoolDescriptor, ports.PoolIDBechFile:
			// a record that carries the pool id: it must be the id of the cold key of the result
			if !both {
				if why := poolRecordIDFailure(r.Kind, a.data, coldID); why != "" {
					c.bad(r, why)
				}
			}
			if a.side == onlyEx && cold != nil && c.coldChanged(cold) {
				c.bad(r, "the import has another cold key than the workspace pool")
			}
		case ports.PoolMetadata, ports.PoolExtendedMetadata, ports.PoolAdditionalMetadata,
			ports.PoolWitnessFile, ports.KesExpire:
			// records of the pool: they stay only if its cold key is not replaced by another
			if a.side == onlyEx && cold != nil && c.coldChanged(cold) {
				c.bad(r, "the import has another cold key than the workspace pool")
			}
		default:
			if !both {
				c.bad(r, "it cannot be shown to belong with the keys of the result")
			}
		}
	}

	// KES counters agree with each other and with the numbered keys.
	kfail := map[ports.Ref]string{}
	knotes := map[ports.Ref]string{}
	checkKesCounters(open, kfail, knotes)
	for r, why := range kfail {
		c.bad(r, why)
	}
	for _, r := range refs {
		if r.Kind == ports.KesCounter && maxKes >= 0 {
			if n, err := pool.ParseCounter(c.res[r].data); err == nil && n < maxKes {
				c.bad(r, fmt.Sprintf("the KES counter is behind the numbered KES key %d of the result", maxKes))
			}
		}
	}

	if len(c.reasons) > 0 {
		sort.Strings(c.reasons)
		why := c.reasons
		if len(why) > 8 {
			why = append(why[:8], fmt.Sprintf("and %d more", len(c.reasons)-8))
		}
		return fmt.Sprintf("it would be stored into the workspace owner %q, and the result is not provably one owner: %s; a merge into an existing owner is accepted only when the result is provably one owner: import it under a new name (--rename), or remove the old owner from the workspace deliberately first", final, strings.Join(why, "; ")), ""
	}

	// Identity anchor: a merge into an existing owner needs something that shows
	// the incoming owner and the workspace's are the same owner of that name. A
	// result that keeps nothing of the workspace's owner (every artefact is
	// replaced) or adds nothing is not a merge and has nothing to show.
	addsSomething, keepsSomething := false, false
	for _, r := range refs {
		addsSomething = addsSomething || c.res[r].side == onlyInc
		keepsSomething = keepsSomething || c.res[r].side == onlyEx
	}
	anchored := ""
	if addsSomething && keepsSomething {
		if anchored = c.identityAnchor(views, keys, refs, final, inspect, hashIs); anchored == "" {
			return fmt.Sprintf("it would be stored into the workspace owner %q, and nothing shows that the source owner and the workspace owner of this name are the same: they share no verification key, hardware public key, cold key named by an issue counter or operational certificate, or address or certificate of one of the workspace owner's keys; import it under a new name (--rename)", final), ""
		}
	}

	var added, replaced []string
	for _, r := range refs {
		switch a := c.res[r]; {
		case a.side == onlyInc && !o.refs[r]:
			added = append(added, r.String())
		case a.side == onlyInc:
			replaced = append(replaced, r.String())
		}
	}
	if len(added) > 0 {
		note = fmt.Sprintf("merged into the existing workspace owner %q; verified: %s, and the keys, addresses, certificates and counters of the result agree; added %s", final, anchored, listCapped(added))
	}
	if len(replaced) > 0 {
		note = joinNotes(note, "replaced "+listCapped(replaced))
		if len(added) == 0 && anchored != "" {
			note = fmt.Sprintf("merged into the existing workspace owner %q; verified: %s, and the keys, addresses, certificates and counters of the result agree; ", final, anchored) + note
		}
	}
	return "", note
}

// identityAnchor says what shows that the incoming artefacts and the
// workspace's owner `final` are one owner, as a clause: a verification key (or
// hardware public key, or a signing key deriving it) the two sides have in
// common, or an artefact of one side that names a key of the other: an issue
// counter, operational certificate, pool certificate or pool id for a cold
// key, a certificate or address for the stake or payment key. Empty when
// nothing does.
func (c *coherence) identityAnchor(views map[slotKey]*slotView, keys []slotKey, refs []ports.Ref, final string,
	inspect func(*resArtefact) (ports.AddressInfo, bool), hashIs func(*txbuild.KeyHash, []byte) bool) string {
	for _, k := range keys {
		if v := views[k]; v.id != nil && v.side == bothSides {
			return fmt.Sprintf("the %s of %q is the same on both sides", k.vk, k.name)
		}
	}
	// the keys of one side: ex is what the workspace holds (and keeps or sees
	// replaced by the same key), inc is what the import brings
	keyOf := func(k slotKey, inc bool) []byte {
		v := views[k]
		if v == nil {
			return nil
		}
		for _, a := range v.arts {
			if (inc && a.side&onlyInc != 0) || (!inc && (a.side == onlyEx || a.side == bothSides)) {
				if id := c.identity(a); id != nil {
					return id
				}
			}
		}
		return nil
	}
	coldOf := func(inc bool) []byte {
		if k := keyOf(slotKey{final, ports.NodeVKey, 0}, inc); k != nil {
			return k
		}
		for _, r := range refs {
			if a := c.res[r]; r.Kind == ports.NodeCounter && ((inc && a.side&onlyInc != 0) || (!inc && (a.side == onlyEx || a.side == bothSides))) {
				if k := counterCold(a.data); k != nil {
					return k
				}
			}
		}
		return nil
	}
	// does artefact a (of one side) name a key of the other side?
	names := func(r ports.Ref, a *resArtefact, other bool) string {
		cold, stake := coldOf(other), keyOf(slotKey{final, ports.StakingVKey, 0}, other)
		if a.data == nil {
			return ""
		}
		switch r.Kind {
		case ports.NodeCounter:
			if k := counterCold(a.data); k != nil && cold != nil && bytes.Equal(k, cold) {
				return r.String() + " names the cold key of the other side"
			}
		case ports.OpCert:
			if oc, err := pool.ParseOpCert(a.data); err == nil && cold != nil && bytes.Equal(oc.ColdVKey[:], cold) {
				return r.String() + " names the cold key of the other side"
			}
		case ports.PoolCert, ports.PoolDeregCert:
			if op := certOperator(a.data); op != nil && cold != nil && bytes.Equal(op, poolIDOf(cold)) {
				return r.String() + " is about the pool id of the cold key of the other side"
			}
		case ports.PoolIDFile:
			if cold != nil && strings.TrimSpace(string(a.data)) == hex.EncodeToString(poolIDOf(cold)) {
				return r.String() + " is the pool id of the cold key of the other side"
			}
		case ports.StakingCert, ports.DelegCert, ports.VoteDelegCert, ports.StakingDeregCert:
			if stake != nil && certNames(a.data, txbuild.HashKey(stake)) {
				return r.String() + " names the stake key of the other side"
			}
		case ports.StakingAddr:
			if info, ok := inspect(a); ok && hashIs(info.StakeKeyHash, stake) {
				return r.String() + " is the stake address of the stake key of the other side"
			}
		case ports.AddrFile:
			if info, ok := inspect(a); ok && (hashIs(info.PaymentKeyHash, keyOf(slotKey{r.Name, ports.AddrVKey, 0}, other)) || (info.StakeKeyHash != nil && hashIs(info.StakeKeyHash, stake))) {
				return r.String() + " is an address of a key of the other side"
			}
		}
		return ""
	}
	for _, r := range refs {
		a := c.res[r]
		if a.side&onlyInc != 0 {
			if why := names(r, a, false); why != "" {
				return why
			}
		}
		if a.side == onlyEx || a.side == bothSides {
			if why := names(r, a, true); why != "" {
				return why
			}
		}
	}
	return ""
}

// coldChanged: the cold key the import brings is not the workspace's.
func (c *coherence) coldChanged(v *slotView) bool {
	if v.side == bothSides || v.side == onlyEx {
		return false
	}
	var ex []byte
	for _, a := range v.arts {
		if a.side != onlyInc {
			if id := c.identity(a); id != nil {
				ex = id
				break
			}
		}
	}
	if ex == nil {
		for r, a := range c.res {
			if r.Kind == ports.NodeCounter && a.side != onlyInc {
				ex = counterCold(a.data)
			}
		}
	}
	return v.id != nil && (ex == nil || !bytes.Equal(ex, v.id))
}

func poolIDOf(coldID []byte) []byte {
	h := txbuild.HashKey(coldID)
	return h[:]
}

// poolRecordIDFailure compares the pool id a descriptor (`poolID`,
// `poolIDbech`) or an id-bech file carries with the pool id of the cold key of
// the result. A record that names no id says nothing.
func poolRecordIDFailure(k ports.Kind, data, coldID []byte) string {
	var ids []string // "field=value"
	if k == ports.PoolIDBechFile {
		if v := strings.TrimSpace(string(data)); v != "" {
			ids = append(ids, "pool id file="+v)
		}
	} else {
		d, err := pool.ParseDescriptor(bytes.TrimPrefix(data, utf8BOM))
		if err != nil {
			return ""
		}
		for _, f := range []string{pool.FieldPoolID, pool.FieldPoolIDBech} {
			if v := d.Text(f); v != "" {
				ids = append(ids, f+"="+v)
			}
		}
	}
	for _, kv := range ids {
		field, v, _ := strings.Cut(kv, "=")
		if coldID == nil {
			return "it names a pool id (" + field + ") and there is no cold key of the result to check it against"
		}
		want := poolIDOf(coldID)
		var got []byte
		if field == pool.FieldPoolID {
			got, _ = hex.DecodeString(strings.ToLower(v))
		} else if id, err := chain.ParsePoolBech32(v); err == nil {
			got = id[:]
		}
		if !bytes.Equal(got, want) {
			return "its " + field + " is not the pool id of the cold key of the result"
		}
	}
	return ""
}

func listCapped(xs []string) string {
	if len(xs) > 8 {
		return strings.Join(xs[:8], ", ") + fmt.Sprintf(" and %d more", len(xs)-8)
	}
	return strings.Join(xs, ", ")
}
