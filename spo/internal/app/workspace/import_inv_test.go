package workspace

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// opcertOf is a NodeOperationalCertificate naming the KES verification key and
// the cold verification key: [[kes, counter 1, period 0, signature], cold].
func opcertOf(cold, kes []byte) []byte {
	b := []byte{0x82, 0x84, 0x58, 0x20}
	b = append(b, kes...)
	b = append(b, 0x01, 0x00, 0x58, 0x40)
	b = append(b, bytes.Repeat([]byte{0x11}, 64)...)
	b = append(b, 0x58, 0x20)
	b = append(b, cold...)
	return pool.MarshalEnvelope(pool.Envelope{Type: pool.TypeOpCert, CborHex: hex.EncodeToString(b)})
}

// invState is what the oracle knows of a run: the source tree, the workspace
// as the test built it, the workspace as it ended, and the renames requested.
type invState struct {
	trs     []*memTree
	dst     *memStore
	pres    []map[ports.Ref]string // the workspace before each import of the test
	renames map[string]string      // source owner name -> stored name
}

// before returns what the workspace held at ref before any import of the test.
func (s *invState) before(r ports.Ref) []string {
	var out []string
	for _, p := range s.pres {
		if v, ok := p[r]; ok {
			out = append(out, v)
		}
	}
	return out
}

func (s *invState) storedName(src string) string {
	if to, ok := s.renames[src]; ok {
		return to
	}
	return src
}

// assertINV006 asserts SPO-Xmulti-INV-006 on the workspace a test run has left.
// It runs at the end of every test that builds an importer with multi.
func assertINV006(t *testing.T, st *invState) {
	t.Helper()
	for _, v := range oracleINV006(st) {
		t.Errorf("INV-006: %s", v)
	}
}

// oraclePair is one name an oracle reads out of a descriptor.
type oracleName struct {
	field, name string
	self        bool
}

// oracleNames reads the names of a descriptor with the domain's own accessors,
// written out here so that the oracle shares nothing with the import's code.
func oracleNames(b []byte) []oracleName {
	d, err := pool.ParseDescriptor(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
	if err != nil {
		return nil
	}
	var out []oracleName
	if owners, legacy, err := d.Owners(); err == nil {
		for i, o := range owners {
			f := "poolOwner[" + strconv.Itoa(i) + "].ownerName"
			if legacy {
				f = "poolOwner"
			}
			out = append(out, oracleName{field: f, name: o.Name})
		}
	}
	if v := d.Text("poolRewards"); v != "" {
		out = append(out, oracleName{field: "poolRewards", name: v})
	}
	if rn, err := d.RegistrationNames(); err == nil {
		if rn.Pay != "" {
			out = append(out, oracleName{field: "regWitness.regPayName", name: rn.Pay})
		}
		for _, k := range rn.Slots {
			n := strings.TrimSuffix(strings.TrimSuffix(k, ".staking"), ".node")
			out = append(out, oracleName{field: fmt.Sprintf("regWitness.witnesses[%q]", k), name: n, self: strings.HasSuffix(k, ".node")})
		}
		for _, tok := range strings.FieldsFunc(rn.MetadataFiles, func(r rune) bool { return strings.ContainsRune(" ,\"'\t\n", r) }) {
			for _, suf := range []string{".metadata.json", ".extended-metadata.json", ".additional-metadata.json"} {
				if n, ok := strings.CutSuffix(path.Base(tok), suf); ok && n != "" {
					out = append(out, oracleName{field: "regWitness.metadataFilesList", name: n, self: true})
					break
				}
			}
		}
	}
	return out
}

// oracleResolve finds the source owner a descriptor in folder dir names by the
// folder rule: a value with a separator is joined to the descriptor's folder
// and only that folder counts; a bare name is the descriptor's own folder's, or
// else the only other folder of the run that has it.
func oracleResolve(tr *memTree, dir, value string) (*memDir, string) {
	has := func(d *memDir, n string) bool {
		for r := range d.files {
			if OwnerOf(r) == n {
				return true
			}
		}
		return false
	}
	v := strings.ReplaceAll(value, `\`, "/")
	if strings.Contains(v, "/") {
		target := path.Join(dir, v)
		if d := tr.dirs[path.Dir(target)]; d != nil && has(d, path.Base(target)) {
			return d, path.Base(target)
		}
		return nil, path.Base(target)
	}
	if d := tr.dirs[dir]; d != nil && has(d, v) {
		return d, v
	}
	var hit *memDir
	for p, d := range tr.dirs {
		if p != dir && has(d, v) {
			if hit != nil {
				return nil, v
			}
			hit = d
		}
	}
	return hit, v
}

// oracleINV006 returns every violation of SPO-Xmulti-INV-006 the workspace in
// st.dst shows, from the files alone: no owner holds another owner's key
// material; every pool's counters, certificates and pool id belong to its cold
// key; and every name a descriptor of the workspace carries is a wallet with a
// stake key that is (i) for a descriptor this run stored, the stake key of the
// source owner the folder rule resolves its source descriptor's value to, or,
// when none is, the workspace's own wallet as it was before the run, and (ii)
// for a descriptor the run did not change, the wallet it was before the run.
func oracleINV006(st *invState) (bad []string) {
	dst := st.dst
	report := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }
	owners := map[string]map[ports.Ref][]byte{}
	for r, b := range dst.files {
		if !ports.IsWorkspaceKind(r.Kind) {
			continue
		}
		n := OwnerOf(r)
		if owners[n] == nil {
			owners[n] = map[ports.Ref][]byte{}
		}
		owners[n][r] = b
	}
	names := make([]string, 0, len(owners))
	for n := range owners {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		arts := owners[n]
		hasWallet, hasPool := false, false
		for r := range arts {
			switch kindOfRefs([]ports.Ref{r}) {
			case KindWallet:
				hasWallet = true
			case KindPool:
				hasPool = true
			}
		}
		if hasWallet && hasPool {
			report("owner %q holds wallet and pool artefacts", n)
		}
		kinfo := func(r ports.Ref) []byte {
			switch roleOf[r.Kind] {
			case 0:
				return rawOf(arts[r])
			case 1:
				sec := sec(string(arts[r]))
				defer sec.Destroy()
				k, _ := edDeriver{}.DeriveVerificationKey(context.Background(), sec)
				return k
			}
			return hwsPubKey(arts[r])
		}
		for r := range arts {
			vk, ok := vkOfKind[r.Kind]
			if !ok || roleOf[r.Kind] == 0 {
				continue
			}
			v := ports.Ref{Name: r.Name, Kind: vk, Num: r.Num}
			if _, have := arts[v]; !have {
				continue
			}
			if k := kinfo(r); k != nil && !bytes.Equal(k, rawOf(arts[v])) {
				report("%s does not belong to %s", r, v)
			}
		}

		// the cold key of a pool, from whatever material it holds, and
		// everything that names it
		var colds [][]byte
		for _, r := range []ports.Ref{{Name: n, Kind: ports.NodeVKey}, {Name: n, Kind: ports.NodeSKey}, {Name: n, Kind: ports.NodeHwsFile}} {
			if _, have := arts[r]; have {
				if k := kinfo(r); k != nil {
					colds = append(colds, k)
				}
			}
		}
		for _, r := range sortedKeys(arts) {
			switch r.Kind {
			case ports.NodeCounter:
				if k := counterCold(arts[r]); k != nil {
					colds = append(colds, k)
				}
			case ports.OpCert:
				if oc, err := pool.ParseOpCert(arts[r]); err == nil {
					colds = append(colds, oc.ColdVKey[:])
				}
			}
		}
		var cold []byte
		for _, c := range colds {
			if cold == nil {
				cold = c
			} else if !bytes.Equal(cold, c) {
				report("%q holds material of more than one cold key", n)
				break
			}
		}
		if cold != nil {
			h := txbuild.HashKey(cold)
			wantHex := hex.EncodeToString(h[:])
			for _, r := range sortedKeys(arts) {
				b := arts[r]
				switch r.Kind {
				case ports.NodeCounter:
					if !bytes.Equal(counterCold(b), cold) {
						report("%s names another cold key", r)
					}
				case ports.OpCert:
					oc, err := pool.ParseOpCert(b)
					if err != nil {
						report("%s unreadable", r)
						continue
					}
					if !bytes.Equal(oc.ColdVKey[:], cold) {
						report("%s names another cold key", r)
					}
					if kv := rawOf(arts[ports.Ref{Name: n, Kind: ports.KesVKey, Num: r.Num}]); kv != nil && !bytes.Equal(oc.KesVKey[:], kv) {
						report("%s names another hot key", r)
					}
				case ports.PoolIDFile:
					if strings.TrimSpace(string(b)) != wantHex {
						report("%s is not the pool id of the cold key", r)
					}
				case ports.PoolIDBechFile:
					if id, err := chain.ParsePoolBech32(strings.TrimSpace(string(b))); err != nil || hex.EncodeToString(id[:]) != wantHex {
						report("%s is not the pool id of the cold key", r)
					}
				case ports.PoolCert, ports.PoolDeregCert:
					if raw := certHex(b); len(raw) >= 32 && raw[2] == 0x58 && raw[3] == 0x1c && !bytes.Equal(raw[4:32], h[:]) {
						report("%s is about another pool id than the cold key's", r)
					}
				case ports.PoolDescriptor:
					if d, err := pool.ParseDescriptor(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))); err == nil {
						if v := d.Text("poolID"); v != "" && strings.ToLower(v) != wantHex {
							report("%s: poolID is not the pool id of the cold key", r)
						}
						if v := d.Text("poolIDbech"); v != "" {
							if id, err := chain.ParsePoolBech32(v); err != nil || hex.EncodeToString(id[:]) != wantHex {
								report("%s: poolIDbech is not the pool id of the cold key", r)
							}
						}
					}
				}
			}
		}
		for _, r := range sortedKeys(arts) {
			b := arts[r]
			if r.Kind == ports.AddrFile {
				info, err := addrInspector{}.InspectAddress(chain.Address(strings.TrimSpace(string(b))))
				if err != nil {
					continue
				}
				if pk := rawOf(arts[ports.Ref{Name: r.Name, Kind: ports.AddrVKey}]); pk != nil && info.PaymentKeyHash != nil && *info.PaymentKeyHash != txbuild.HashKey(pk) {
					report("%s is not derived from the payment key of its name", r)
				}
				if sk := rawOf(owners[n][ports.Ref{Name: n, Kind: ports.StakingVKey}]); sk != nil && info.StakeKeyHash != nil && *info.StakeKeyHash != txbuild.HashKey(sk) {
					report("%s is not derived from the stake key of its owner", r)
				}
			}
		}
	}

	// a payment key and a stake key belong together only if a base address ties
	// them, they were together in the workspace before, or they come together
	// from one source owner
	for _, n := range names {
		arts := owners[n]
		S := rawOf(arts[ports.Ref{Name: n, Kind: ports.StakingVKey}])
		P := rawOf(arts[ports.Ref{Name: n + ".payment", Kind: ports.AddrVKey}])
		if S == nil || P == nil {
			continue
		}
		ok := false
		if b, have := arts[ports.Ref{Name: n + ".payment", Kind: ports.AddrFile}]; have {
			if info, err := (addrInspector{}).InspectAddress(chain.Address(strings.TrimSpace(string(b)))); err == nil && info.PaymentKeyHash != nil && info.StakeKeyHash != nil {
				ok = *info.PaymentKeyHash == txbuild.HashKey(P) && *info.StakeKeyHash == txbuild.HashKey(S)
			}
		}
		for _, pre := range st.pres {
			ok = ok || (bytes.Equal(rawOf([]byte(pre[ports.Ref{Name: n, Kind: ports.StakingVKey}])), S) && bytes.Equal(rawOf([]byte(pre[ports.Ref{Name: n + ".payment", Kind: ports.AddrVKey}])), P))
		}
		for _, tr := range st.trs {
			for _, d := range tr.dirs {
				for sr, sb := range d.files {
					if sr.Kind == ports.StakingVKey && st.storedName(sr.Name) == n && bytes.Equal(rawOf(sb), S) && bytes.Equal(rawOf(d.files[ports.Ref{Name: sr.Name + ".payment", Kind: ports.AddrVKey}]), P) {
						ok = true
					}
				}
			}
		}
		if !ok {
			report("owner %q holds stake and payment keys that nothing ties together", n)
		}
	}

	// every name a descriptor of the workspace carries
	wsStake := func(n string) []byte { return rawOf(owners[n][ports.Ref{Name: n, Kind: ports.StakingVKey}]) }
	wasStake := func(n string, k []byte) bool {
		for _, v := range st.before(ports.Ref{Name: n, Kind: ports.StakingVKey}) {
			if bytes.Equal(rawOf([]byte(v)), k) {
				return true
			}
		}
		return false
	}
	everHad := func(n string) bool { return len(st.before(ports.Ref{Name: n, Kind: ports.StakingVKey})) > 0 }
	descs := make([]ports.Ref, 0)
	for r := range dst.files {
		if r.Kind == ports.PoolDescriptor {
			descs = append(descs, r)
		}
	}
	sort.Slice(descs, func(i, j int) bool { return descs[i].Name < descs[j].Name })
	for _, r := range descs {
		b := dst.files[r]
		unchanged := slices.Contains(st.before(r), string(b))
		for _, nr := range oracleNames(b) {
			who := func(why string) {
				report("the descriptor of %s names %q in %s: %s", r.Name, nr.name, nr.field, why)
			}
			if nr.self {
				if nr.name != r.Name {
					who("it names another pool than its own")
				}
				continue
			}
			stake := wsStake(nr.name)
			if unchanged {
				// a descriptor the run left alone: the wallet it names is the one it was
				if everHad(nr.name) && (stake == nil || !wasStake(nr.name, stake)) {
					who("the run changed the wallet a pool it did not replace names")
				}
				continue
			}
			if stake == nil {
				who("no wallet of the workspace has that name")
				continue
			}
			var problems [][]string
			cands := 0
			for _, tr := range st.trs {
				for dir, d := range tr.dirs {
					for sr, sb := range d.files {
						if sr.Kind != ports.PoolDescriptor || st.storedName(sr.Name) != r.Name {
							continue
						}
						cands++
						var ps []string
						var v string
						found := false
						for _, x := range oracleNames(sb) {
							if x.field == nr.field {
								v, found = x.name, true
							}
						}
						if !found {
							problems = append(problems, []string{"the source descriptor has no such field"})
							continue
						}
						sd, want := oracleResolve(tr, dir, v)
						switch {
						case sd != nil:
							if !bytes.Equal(rawOf(sd.files[ports.Ref{Name: want, Kind: ports.StakingVKey}]), stake) {
								ps = append(ps, "the workspace wallet has other stake keys than the source owner the layout names")
							}
							srcPay := rawOf(sd.files[ports.Ref{Name: want + ".payment", Kind: ports.AddrVKey}])
							if pay := rawOf(owners[nr.name][ports.Ref{Name: nr.name + ".payment", Kind: ports.AddrVKey}]); pay != nil && srcPay != nil && !bytes.Equal(pay, srcPay) {
								ps = append(ps, "the workspace wallet has other payment keys than the source owner the layout names")
							}
						default:
							for _, t2 := range st.trs {
								for _, d2 := range t2.dirs {
									for sr2 := range d2.files {
										if o2 := OwnerOf(sr2); o2 != want && strings.EqualFold(o2, want) && sr2.Kind == ports.StakingVKey {
											ps = append(ps, "a source wallet "+o2+" differs only by case")
										}
									}
								}
							}
							if !wasStake(want, stake) {
								ps = append(ps, "no source owner is named and the wallet is not the workspace's own as it was")
							}
						}
						problems = append(problems, ps)
					}
				}
			}
			if cands == 0 {
				if everHad(nr.name) && !wasStake(nr.name, stake) {
					who("no source descriptor is behind it and the wallet is not the workspace's own as it was")
				}
				continue
			}
			ok := false
			for _, ps := range problems {
				ok = ok || len(ps) == 0
			}
			if !ok {
				who(strings.Join(problems[0], "; "))
			}
		}
	}
	return bad
}

func sortedKeys(m map[ports.Ref][]byte) []ports.Ref {
	out := make([]ports.Ref, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// certHex is the CBOR of a certificate envelope.
func certHex(b []byte) []byte {
	env, err := pool.ParseEnvelope(b)
	if err != nil {
		return nil
	}
	raw, _ := hex.DecodeString(env.CborHex)
	return raw
}
