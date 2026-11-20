package deploy

import (
	"crypto/rand"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

// pod is what the checks need of one relay instance's pod.
type pod struct {
	at     string
	ps     map[string]any
	relay  map[string]any // the serve container
	init   map[string]any // the init container that installs the key
	claims map[string]bool
}

func pods(tr tree) ([]pod, []instance, []string) {
	docs, bad := tr.decodeAll()
	l, lbad := tr.readLayout()
	bad = append(bad, lbad...)
	var out []pod
	for _, d := range workloads(docs, l) {
		ps := podSpec(d)
		p := pod{at: d.file + ": " + d.name(), ps: ps, relay: relayContainer(ps), claims: map[string]bool{}}
		inits := seq(ps["initContainers"])
		if len(inits) == 1 {
			p.init = mp(inits[0])
		} else {
			bad = append(bad, p.at+": not exactly one init container")
		}
		if p.relay == nil {
			bad = append(bad, p.at+": no container runs spo-relay serve")
		}
		for _, c := range seq(get(d.m, "spec", "volumeClaimTemplates")) {
			p.claims[str(get(c, "metadata", "name"))] = true
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		bad = append(bad, "no relay workload")
	}
	return out, l.instances, bad
}

// resolve maps a path in a container to the volume that holds it and the path
// inside that volume ("" for its root).
func resolve(c map[string]any, p string) (vol, rest string, ok bool) {
	best := -1
	for _, m := range seq(c["volumeMounts"]) {
		mpth := str(get(m, "mountPath"))
		if (p == mpth || strings.HasPrefix(p, mpth+"/")) && len(mpth) > best {
			best = len(mpth)
			vol, rest = str(get(m, "name")), strings.TrimPrefix(strings.TrimPrefix(p, mpth), "/")
			ok = true
		}
	}
	return vol, rest, ok
}

// The init script, in the only form it may take.
type initOp struct {
	dir      bool
	mode     os.FileMode
	src, dst string   // a file install
	dirs     []string // a directory install
}

func parseInit(c map[string]any) ([]initOp, error) {
	cmd := seq(c["command"])
	if len(cmd) != 3 || str(cmd[0]) != "/bin/sh" || str(cmd[1]) != "-c" || c["args"] != nil {
		return nil, fmt.Errorf("the init container's command is not /bin/sh -c SCRIPT")
	}
	lines := strings.Split(strings.TrimSpace(str(cmd[2])), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "set -eu" {
		return nil, fmt.Errorf("the init script does not start with set -eu")
	}
	var ops []initOp
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		op := initOp{}
		switch {
		case len(f) >= 5 && f[0] == "install" && f[1] == "-d" && f[2] == "-m":
			op.dir, op.dirs = true, f[4:]
		case len(f) == 5 && f[0] == "install" && f[1] == "-m":
			op.src, op.dst = f[3], f[4]
		default:
			return nil, fmt.Errorf("the init script line %q is not set -eu or an install", l)
		}
		mode, err := strconv.ParseUint(f[map[bool]int{true: 3, false: 2}[op.dir]], 8, 32)
		if err != nil {
			return nil, fmt.Errorf("the init script line %q: mode: %v", l, err)
		}
		op.mode = os.FileMode(mode)
		ops = append(ops, op)
	}
	return ops, nil
}

// checkRelayConfig: each instance's relay.toml passes the real parser and the
// load-time rules, and the pod gives it what it names: the file at the path of
// --config through a ConfigMap mount that is updated in place (no subPath, no
// name hash, so SIGHUP reloads it), the key in the memory volume and the stores
// on the claim, in directories the init container makes.
func checkRelayConfig(tr tree) []string {
	ps, ins, bad := pods(tr)
	if len(ins) == 0 {
		bad = append(bad, "no relay instance (a kustomization with a configMapGenerator)")
	}
	for _, in := range ins {
		at := in.dir
		k, err := kustomization(tr, in.dir)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		if get(k, "generatorOptions", "disableNameSuffixHash") != true {
			bad = append(bad, at+": the ConfigMap gets a name hash; a change then restarts the pod instead of a SIGHUP reload, and the old map is left behind")
		}
		gens := seq(k["configMapGenerator"])
		if len(gens) != 1 || len(seq(get(gens[0], "files"))) != 1 || str(seq(get(gens[0], "files"))[0]) != "relay.toml" {
			bad = append(bad, at+": the generator does not make exactly relay.toml")
			continue
		}
		src, ok := tr[in.config]
		if !ok {
			bad = append(bad, at+": no "+in.config)
			continue
		}
		cfg, err := relayconfig.Parse([]byte(src))
		if err == nil {
			_, err = relayhost.Prepare(cfg)
		}
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: the relay refuses it: %v", in.config, err))
			continue
		}
		var p *pod
		for i := range ps {
			if strings.HasPrefix(ps[i].at, in.statefulSet.file+":") {
				p = &ps[i]
			}
		}
		if p == nil || p.relay == nil || p.init == nil {
			continue
		}
		bad = append(bad, podGivesConfig(*p, cfg, str(get(gens[0], "name")), in.config)...)
	}
	return bad
}

func podGivesConfig(p pod, cfg *relayconf.Config, mapName, file string) []string {
	var bad []string
	at := p.at
	args := seq(p.relay["args"])
	if len(args) != 3 || str(args[1]) != "--config" {
		return append(bad, at+": the relay's args are not serve --config FILE")
	}
	conf := str(args[2])
	vol, rest, ok := resolve(p.relay, conf)
	v := volume(p.ps, vol)
	switch {
	case !ok || v == nil || str(get(v, "configMap", "name")) != mapName:
		bad = append(bad, fmt.Sprintf("%s: --config %s is not in the ConfigMap %s", at, conf, mapName))
	case rest != "relay.toml":
		bad = append(bad, fmt.Sprintf("%s: --config %s is not the generated relay.toml", at, conf))
	}
	if m := mountOf(p.relay, vol); m == nil || m["readOnly"] != true || m["subPath"] != nil || m["subPathExpr"] != nil {
		bad = append(bad, at+": the configuration is not mounted read-only as a whole directory (a subPath mount is never updated, so a reload would read the old file)")
	}
	if len(seq(get(v, "configMap", "items"))) > 0 {
		bad = append(bad, at+": the ConfigMap volume lists items")
	}
	// where the relay's paths land
	keyVol, keyRest, ok1 := resolve(p.relay, cfg.KeyFile)
	mbVol, mbRest, ok2 := resolve(p.relay, cfg.MailboxDir)
	rgVol, rgRest, ok3 := resolve(p.relay, cfg.RegistryDir)
	if !ok1 || !ok2 || !ok3 {
		return append(bad, fmt.Sprintf("%s: %s names a path that the relay container does not mount", at, file))
	}
	if kv := volume(p.ps, keyVol); kv == nil || str(get(kv, "emptyDir", "medium")) != "Memory" {
		bad = append(bad, fmt.Sprintf("%s: key_file %s is not in a memory emptyDir (the key must not land on the claim or the node's disk)", at, cfg.KeyFile))
	}
	if m := mountOf(p.relay, keyVol); m == nil || m["readOnly"] != true {
		bad = append(bad, at+": the relay mounts its key directory writable")
	}
	for _, x := range []struct{ what, vol string }{{"mailbox_dir", mbVol}, {"registry_dir", rgVol}} {
		if !p.claims[x.vol] || volume(p.ps, x.vol) != nil {
			bad = append(bad, fmt.Sprintf("%s: %s is not on the pod's own claim from volumeClaimTemplates", at, x.what))
		}
	}
	// the init container makes the directories and installs the key
	ops, err := parseInit(p.init)
	if err != nil {
		return append(bad, at+": "+err.Error())
	}
	made := map[string]os.FileMode{}
	installed := map[string]os.FileMode{}
	for _, op := range ops {
		if op.dir {
			for _, d := range op.dirs {
				dv, dr, ok := resolve(p.init, d)
				if !ok {
					bad = append(bad, at+": the init container makes "+d+" outside its mounts")
				}
				made[dv+":"+dr] = op.mode
			}
			continue
		}
		sv, _, ok := resolve(p.init, op.src)
		if sv2 := volume(p.ps, sv); !ok || sv2 == nil || sv2["secret"] == nil {
			bad = append(bad, at+": the init container installs "+op.src+", which is not in the key Secret")
		}
		dv, dr, _ := resolve(p.init, op.dst)
		installed[dv+":"+dr] = op.mode
	}
	if m, ok := installed[keyVol+":"+keyRest]; !ok {
		bad = append(bad, at+": the init container does not install the key at key_file "+cfg.KeyFile)
	} else if m&0o077 != 0 {
		bad = append(bad, fmt.Sprintf("%s: the key is installed with mode %o; the relay refuses group or other bits", at, m))
	}
	for _, x := range []struct {
		what      string
		vol, rest string
	}{{"key_file", keyVol, keyRest}, {"mailbox_dir", mbVol, mbRest}, {"registry_dir", rgVol, rgRest}} {
		parent := path.Dir(x.rest)
		if parent == "." {
			bad = append(bad, fmt.Sprintf("%s: %s sits at the root of its volume, which kubelet makes group-writable (fsGroup); the relay refuses that parent", at, x.what))
			continue
		}
		m, ok := made[x.vol+":"+parent]
		if !ok {
			bad = append(bad, fmt.Sprintf("%s: the directory of %s is not made by the init container", at, x.what))
		} else if m&0o077 != 0 {
			bad = append(bad, fmt.Sprintf("%s: the directory of %s is made with mode %o; the relay refuses group or other bits", at, x.what, m))
		}
	}
	return bad
}

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now() }

// checkMounts: the files the pod gives the relay pass the binary's own checks.
// The volumes are laid out in a temporary directory as kubelet makes them
// (SPO-Xmailbox-SEC-077, PRE-063; the Kubernetes facts are from memory and
// listed in the how-to): a ConfigMap or Secret file is a link into ..data, with
// the volume's defaultMode and the group read bits that fsGroup adds; the
// claim's and the emptyDir's roots get the fsGroup's group write and setgid.
// Then the init script runs, and the real relayconfig.Load, relayhost.Prepare,
// relayconfig.LoadKey and the two stores' Open must accept the result. What
// cannot be laid out here: that the ConfigMap file belongs to root (the test
// cannot chown; Load accepts root as the owner, as it accepts the user).
func checkMounts(tr tree) []string {
	ps, ins, bad := pods(tr)
	for _, in := range ins {
		var p *pod
		for i := range ps {
			if strings.HasPrefix(ps[i].at, in.statefulSet.file+":") {
				p = &ps[i]
			}
		}
		if p == nil || p.relay == nil || p.init == nil {
			continue
		}
		if err := simulate(*p, tr[in.config]); err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", p.at, err))
		}
	}
	return bad
}

func simulate(p pod, toml string) error {
	root, err := os.MkdirTemp("", "relay-pod-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	fsGroup, _ := num(get(p.ps, "securityContext", "fsGroup"))
	vols := map[string]string{}
	host := func(c map[string]any, cp string) (string, error) {
		v, rest, ok := resolve(c, cp)
		if !ok {
			return "", fmt.Errorf("%s is not mounted", cp)
		}
		d, ok := vols[v]
		if !ok {
			return "", fmt.Errorf("the volume %s is not laid out", v)
		}
		return filepath.Join(d, rest), nil
	}
	// the claims and the pod's volumes
	names := []string{}
	for c := range p.claims {
		names = append(names, c)
	}
	for _, v := range seq(p.ps["volumes"]) {
		names = append(names, str(get(v, "name")))
	}
	for _, n := range names {
		vols[n] = filepath.Join(root, "vol", n)
	}
	// the relay's view: its paths rewritten to the laid-out volumes
	cfg, err := relayconfig.Parse([]byte(toml))
	if err != nil {
		return err
	}
	rewritten := toml
	for _, cp := range []string{cfg.KeyFile, cfg.MailboxDir, cfg.RegistryDir} {
		hp, err := host(p.relay, cp)
		if err != nil {
			return err
		}
		rewritten = strings.Replace(rewritten, `"`+cp+`"`, `"`+hp+`"`, 1)
	}
	for _, n := range names {
		d := vols[n]
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		v := volume(p.ps, n)
		switch {
		case p.claims[n] || v["emptyDir"] != nil:
			// kubelet: fsGroup as the group, group rwx and setgid on the root
			// (an emptyDir's root is 0777 to begin with)
			mode := os.FileMode(0o755)
			if v["emptyDir"] != nil {
				mode = 0o777
			}
			if fsGroup != 0 {
				mode |= 0o770 | os.ModeSetgid
			} else if p.claims[n] {
				// a provisioned volume's root belongs to root (it does on the
				// common provisioners), so uid 10001 could not make a directory
				return fmt.Errorf("without fsGroup the relay's user cannot write the root of the claim %s", n)
			}
			if err := os.Chmod(d, mode); err != nil {
				return err
			}
		case v["configMap"] != nil || v["secret"] != nil:
			src := map[string]string{}
			kind := "configMap"
			if v["secret"] != nil {
				kind = "secret"
				for _, it := range seq(get(v, "secret", "items")) {
					src[str(get(it, "path"))] = keyFileText()
				}
				if len(src) == 0 {
					return fmt.Errorf("the key Secret volume lists no items")
				}
			} else {
				src["relay.toml"] = rewritten
			}
			dm, ok := num(get(v, kind, "defaultMode"))
			if !ok {
				dm = 0o644 // kubelet's default
			}
			mode := os.FileMode(dm)
			if fsGroup != 0 {
				mode |= 0o440 // the read-only mask of an atomic-writer volume
			}
			data := filepath.Join(d, "..data")
			if err := os.Mkdir(data, 0o755); err != nil {
				return err
			}
			for name, body := range src {
				f := filepath.Join(data, name)
				if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
					return err
				}
				if err := os.Chmod(f, mode); err != nil {
					return err
				}
				if err := os.Symlink(filepath.Join("..data", name), filepath.Join(d, name)); err != nil {
					return err
				}
				// the file belongs to root, its group is fsGroup's when there is one
				if mode&0o004 == 0 && (fsGroup == 0 || mode&0o040 == 0) {
					return fmt.Errorf("the %s file %s has mode %o and belongs to root: uid %d cannot read it", kind, name, mode, relayUID)
				}
			}
		}
	}
	// the init script
	ops, err := parseInit(p.init)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op.dir {
			for _, cd := range op.dirs {
				hd, err := host(p.init, cd)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(hd, 0o700); err != nil {
					return err
				}
				if err := os.Chmod(hd, op.mode); err != nil {
					return err
				}
			}
			continue
		}
		hs, err := host(p.init, op.src)
		if err != nil {
			return err
		}
		hd, err := host(p.init, op.dst)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(hs)
		if err != nil {
			return err
		}
		if err := os.WriteFile(hd, b, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(hd, op.mode); err != nil {
			return err
		}
	}
	args := seq(p.relay["args"])
	if len(args) == 0 {
		return fmt.Errorf("the relay has no args")
	}
	confPath, err := host(p.relay, str(args[len(args)-1]))
	if err != nil {
		return err
	}
	loaded, err := relayconfig.Load(confPath)
	if err != nil {
		return fmt.Errorf("relayconfig.Load: %w", err)
	}
	if _, err := relayhost.Prepare(loaded); err != nil {
		return fmt.Errorf("relayhost.Prepare: %w", err)
	}
	k, err := relayconfig.LoadKey(loaded.KeyFile)
	if err != nil {
		return fmt.Errorf("relayconfig.LoadKey: %w", err)
	}
	k.Destroy()
	ms, _, err := mailboxstore.Open(loaded.MailboxDir, sysClock{})
	if err != nil {
		return fmt.Errorf("the mailbox store: %w", err)
	}
	ms.Close()
	rs, _, err := bindingstore.Open(loaded.RegistryDir, loaded.Registry, sysClock{})
	if err != nil {
		return fmt.Errorf("the registry: %w", err)
	}
	rs.Close()
	return nil
}

// keyFileText is a fresh relay key file, made in the test (never a literal).
func keyFileText() string {
	k := &relayconf.Key{}
	rand.Read(k.Node[:])
	rand.Read(k.PSK[:])
	defer k.Destroy()
	return string(relayconfig.EncodeKey(k))
}

// checkGrace: the pod's grace period leaves the relay its whole teardown bound
// and a margin; a SIGKILL inside the bound would cut the teardown that
// SPO-Xmailbox-OUT-101 bounds.
func checkGrace(tr tree) []string {
	ps, _, bad := pods(tr)
	need := int64(relayhost.DefaultTeardown/time.Second) + graceMargin
	for _, p := range ps {
		g, ok := num(p.ps["terminationGracePeriodSeconds"])
		if !ok || g < need {
			bad = append(bad, fmt.Sprintf("%s: terminationGracePeriodSeconds %v is below the teardown bound %v plus %d s", p.at, p.ps["terminationGracePeriodSeconds"], relayhost.DefaultTeardown, graceMargin))
		}
		if p.relay != nil && get(p.relay, "lifecycle", "preStop") != nil {
			bad = append(bad, p.at+": a preStop hook (it runs inside the grace period, before the SIGTERM the relay acts on)")
		}
	}
	return bad
}

// checkOneRelayPerKey: one pod per StatefulSet (one key is one live endpoint
// and each store is one process's, by a flock), the stores on that pod's own
// claim, the key Secret seen only by the init container, and no two instances
// with one Secret or one name.
func checkOneRelayPerKey(tr tree) []string {
	docs, bad := tr.decodeAll()
	l, _ := tr.readLayout()
	for _, d := range workloads(docs, l) {
		at := d.file + ": " + d.name()
		if n, ok := num(get(d.m, "spec", "replicas")); !ok || n != 1 {
			bad = append(bad, at+": replicas is not 1 (more replicas would share one relay key; run more relays as more instances)")
		}
		if str(get(d.m, "spec", "podManagementPolicy")) == "Parallel" {
			bad = append(bad, at+": podManagementPolicy Parallel")
		}
		if t := str(get(d.m, "spec", "updateStrategy", "type")); t != "RollingUpdate" {
			bad = append(bad, at+": updateStrategy is not RollingUpdate (with one replica the old pod is gone before the new one starts)")
		}
		claims := seq(get(d.m, "spec", "volumeClaimTemplates"))
		if len(claims) != 1 {
			bad = append(bad, at+": not exactly one volumeClaimTemplate")
		}
		for _, c := range claims {
			modes := seq(get(c, "spec", "accessModes"))
			if len(modes) != 1 || (str(modes[0]) != "ReadWriteOncePod" && str(modes[0]) != "ReadWriteOnce") {
				bad = append(bad, at+": the claim is not ReadWriteOncePod or ReadWriteOnce")
			}
		}
		if str(get(d.m, "spec", "persistentVolumeClaimRetentionPolicy", "whenDeleted")) != "Retain" {
			bad = append(bad, at+": the claim is not retained when the StatefulSet is deleted")
		}
		ps := podSpec(d)
		for _, v := range seq(ps["volumes"]) {
			if mp(v)["persistentVolumeClaim"] != nil {
				bad = append(bad, at+": a pod volume names a claim (a claim named in the template is one claim for every pod)")
			}
		}
		secrets := 0
		for _, v := range seq(ps["volumes"]) {
			if mp(v)["secret"] == nil {
				continue
			}
			secrets++
			name := str(get(v, "name"))
			for _, c := range seq(ps["containers"]) {
				if mountOf(mp(c), name) != nil {
					bad = append(bad, fmt.Sprintf("%s: the container %s mounts the key Secret (only the init container may)", at, str(get(c, "name"))))
				}
			}
		}
		if secrets != 1 {
			bad = append(bad, at+": not exactly one Secret volume (the relay key)")
		}
	}
	secretOwner, suffixOwner := map[string]string{}, map[string]string{}
	for _, in := range l.instances {
		if in.secret == "" {
			bad = append(bad, in.dir+": no key Secret")
		}
		if o, dup := secretOwner[in.secret]; dup {
			bad = append(bad, fmt.Sprintf("%s and %s use one key Secret %q: two relays with one key", o, in.dir, in.secret))
		}
		secretOwner[in.secret] = in.dir
		if o, dup := suffixOwner[in.suffix]; dup {
			bad = append(bad, fmt.Sprintf("%s and %s build StatefulSets of one name (nameSuffix %q): one would replace the other", o, in.dir, in.suffix))
		}
		suffixOwner[in.suffix] = in.dir
	}
	return bad
}

// checkNetworkPolicy: a policy that denies every ingress and egress of every
// pod in the namespace, and one for the relay that allows only what the tunnel
// needs (DNS, then TCP 443 and UDP 3478 to public addresses for the DERP map,
// the DERP relays and STUN) and no ingress at all: the relay opens no pod port,
// and replies to its own connections are allowed by the policy's connection
// tracking.
func checkNetworkPolicy(tr tree) []string {
	docs, bad := tr.decodeAll()
	denyAll, relay := false, false
	for _, d := range docs {
		if d.kind() != "NetworkPolicy" {
			continue
		}
		at := d.file + ": " + d.name()
		spec := mp(d.m["spec"])
		types := map[string]bool{}
		for _, t := range seq(spec["policyTypes"]) {
			types[str(t)] = true
		}
		if !types["Ingress"] || !types["Egress"] {
			bad = append(bad, at+": policyTypes is not Ingress and Egress (a missing type is not restricted by this policy)")
		}
		if spec["ingress"] != nil {
			bad = append(bad, at+": an ingress rule (nothing may open a connection to a relay pod)")
		}
		sel := mp(spec["podSelector"])
		switch {
		case sel != nil && len(sel) == 0:
			if spec["egress"] != nil {
				bad = append(bad, at+": the namespace-wide policy allows egress")
			}
			denyAll = true
		case str(get(sel, "matchLabels", relayName)) == relayLabel:
			relay = true
			bad = append(bad, relayEgress(at, seq(spec["egress"]))...)
		default:
			bad = append(bad, at+": a policy that selects neither every pod nor the relay")
		}
	}
	if !denyAll {
		bad = append(bad, "no default-deny NetworkPolicy (podSelector {}, both types, no rules)")
	}
	if !relay {
		bad = append(bad, "no NetworkPolicy for the relay")
	}
	return bad
}

// mustExclude are the ranges that the relay's public egress must not reach: the
// cloud metadata address, private and shared ranges (the cluster's own) and
// loopback.
var mustExclude = map[string][]string{
	"0.0.0.0/0": {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8"},
	"::/0":      {"fc00::/7", "fe80::/10", "::1/128"},
}

func relayEgress(at string, rules []any) []string {
	var bad []string
	dns, public := false, false
	for _, r := range rules {
		ports := map[string]bool{}
		for _, p := range seq(get(r, "ports")) {
			n, _ := num(get(p, "port"))
			if get(p, "endPort") != nil {
				bad = append(bad, at+": a port range")
			}
			ports[fmt.Sprintf("%s/%d", str(get(p, "protocol")), n)] = true
		}
		to := seq(get(r, "to"))
		if len(to) == 0 || len(ports) == 0 {
			bad = append(bad, at+": an egress rule without destinations or ports allows everything it leaves open")
			continue
		}
		switch {
		case len(ports) == 2 && ports["UDP/53"] && ports["TCP/53"]:
			for _, t := range to {
				if str(get(t, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")) != "kube-system" ||
					str(get(t, "podSelector", "matchLabels", "k8s-app")) != "kube-dns" || get(t, "ipBlock") != nil {
					bad = append(bad, at+": DNS is allowed to something other than the cluster's DNS pods")
				}
			}
			dns = true
		case len(ports) == 2 && ports["TCP/443"] && ports["UDP/3478"]:
			for _, t := range to {
				cidr := str(get(t, "ipBlock", "cidr"))
				want, known := mustExclude[cidr]
				if !known {
					bad = append(bad, at+": the tunnel's egress goes to "+cidr+" (only 0.0.0.0/0 and ::/0 with the private ranges excluded)")
					continue
				}
				have := map[string]bool{}
				for _, e := range seq(get(t, "ipBlock", "except")) {
					have[str(e)] = true
				}
				for _, w := range want {
					if !have[w] {
						bad = append(bad, fmt.Sprintf("%s: the tunnel's egress to %s does not exclude %s", at, cidr, w))
					}
				}
			}
			public = true
		default:
			bad = append(bad, fmt.Sprintf("%s: an egress rule for ports %v, which the tunnel does not need", at, ports))
		}
	}
	if !dns || !public {
		bad = append(bad, at+": the relay's egress lacks DNS or the tunnel's ports")
	}
	return bad
}

// checkProbes: spo-relay has no health endpoint and no ready file, so no probe:
// an HTTP or TCP probe would always fail, and an exec probe of check-config
// would kill a serving relay over a configuration that its reload has already
// refused (the how-to says why and what a probe would need).
func checkProbes(tr tree) []string {
	ps, _, bad := pods(tr)
	for _, p := range ps {
		for name, c := range containers(p.ps) {
			for _, f := range []string{"livenessProbe", "readinessProbe", "startupProbe"} {
				if c[f] != nil {
					bad = append(bad, fmt.Sprintf("%s: %s: a %s, which spo-relay does not offer", p.at, name, f))
				}
			}
		}
	}
	return bad
}

// checkDisruption: exactly one PodDisruptionBudget over all relays of the
// namespace, so that a drain takes at most one relay at a time (two budgets over
// one pod make every eviction of it fail).
func checkDisruption(tr tree) []string {
	docs, bad := tr.decodeAll()
	l, _ := tr.readLayout()
	n := 0
	for _, d := range docs {
		if d.kind() != "PodDisruptionBudget" || !l.resources[d.file] {
			continue
		}
		n++
		spec := mp(d.m["spec"])
		sel := mp(get(spec, "selector", "matchLabels"))
		if len(sel) != 1 || str(sel[relayName]) != relayLabel {
			bad = append(bad, d.file+": the budget does not select every relay by "+relayName)
		}
		if m, ok := num(spec["maxUnavailable"]); !ok || m != 1 || spec["minAvailable"] != nil {
			bad = append(bad, d.file+": the budget is not maxUnavailable 1")
		}
	}
	if n != 1 {
		bad = append(bad, fmt.Sprintf("%d disruption budgets; one, over all relays", n))
	}
	return bad
}

// checkResources: every container has requests and a memory limit, and the
// relay has GOMEMLIMIT below its limit.
func checkResources(tr tree) []string {
	ps, _, bad := pods(tr)
	for _, p := range ps {
		for name, c := range containers(p.ps) {
			r := mp(c["resources"])
			for _, f := range []string{"requests/cpu", "requests/memory", "limits/memory", "limits/ephemeral-storage"} {
				k := strings.Split(f, "/")
				if str(get(r, k[0], k[1])) == "" {
					bad = append(bad, fmt.Sprintf("%s: %s: no %s", p.at, name, f))
				}
			}
		}
		if p.relay != nil {
			found := false
			for _, e := range seq(p.relay["env"]) {
				if str(get(e, "name")) == "GOMEMLIMIT" && str(get(e, "value")) != "" {
					found = true
				}
			}
			if !found {
				bad = append(bad, p.at+": no GOMEMLIMIT for the relay")
			}
		}
	}
	return bad
}

// checkContainerfile: a static build of cmd/spo-relay on a distroless static
// or scratch base, run as the pod's user.
func checkContainerfile(tr tree) []string {
	src, ok := tr["Containerfile"]
	if !ok {
		return []string{"no Containerfile"}
	}
	var bad []string
	var froms []string
	user := ""
	for _, line := range strings.Split(src, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "FROM":
			froms = append(froms, f[1])
		case "USER":
			user = f[1]
		}
	}
	if len(froms) == 0 {
		return []string{"Containerfile: no FROM"}
	}
	last := froms[len(froms)-1]
	if !strings.HasPrefix(last, "gcr.io/distroless/static") && !strings.HasPrefix(last, "scratch") {
		bad = append(bad, "Containerfile: the final base is neither distroless static nor scratch: "+last)
	}
	if user != fmt.Sprintf("%d:%d", relayUID, relayUID) {
		bad = append(bad, fmt.Sprintf("Containerfile: USER %q is not %d:%d", user, relayUID, relayUID))
	}
	for _, want := range []string{"CGO_ENABLED=0", "./cmd/spo-relay", "-trimpath"} {
		if !strings.Contains(src, want) {
			bad = append(bad, "Containerfile: no "+want)
		}
	}
	if strings.Contains(src, "cmd/spo\n") || strings.Contains(src, "./cmd/spo ") {
		bad = append(bad, "Containerfile: builds spo, not only spo-relay")
	}
	return bad
}

// checkPatches: an overlay's patch may only rename the key Secret, so that no
// patch can weaken what the checks above saw in the base.
func checkPatches(tr tree) []string {
	l, bad := tr.readLayout()
	for p := range l.patches {
		ds, err := decodeYAML(tr[p])
		if err != nil || len(ds) != 1 {
			bad = append(bad, p+": not one document")
			continue
		}
		d := ds[0]
		want := map[string]any{
			"apiVersion": d["apiVersion"], "kind": "StatefulSet",
			"metadata": map[string]any{"name": get(d, "metadata", "name"), "namespace": get(d, "metadata", "namespace")},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"volumes": []any{
				map[string]any{"name": "relay-key", "secret": map[string]any{"secretName": secretOf(d)}},
			}}}},
		}
		if fmt.Sprint(d) != fmt.Sprint(want) || secretOf(d) == "" {
			bad = append(bad, p+": a patch that does more than set the relay-key volume's secretName")
		}
	}
	return bad
}
