// Package deploy checks the Kubernetes manifests of the relay
// (deploy/kubernetes/relay, ADR 0012 stage 6) against what the spo-relay binary
// demands: the pod security of the restricted Pod Security Standard, no literal
// secret, pinned images, a relay configuration that the real parser accepts,
// mounts that the binary's own file checks accept, a grace period above the
// teardown bound, one key and one volume per relay, and a default-deny network
// policy. Nothing here talks to a cluster; the manifests are read as files.
//
// The manifests are outside the Go module (the Nix build copies spo/ only), so
// the tests skip when the directory is not there.
package deploy

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// manifestDir is the manifests' directory, from this package's directory.
const manifestDir = "../../../deploy/kubernetes/relay"

// The fixed facts the manifests are checked against.
const (
	relayUID       = 10001
	relayNamespace = "spo-relay"
	relayName      = "app.kubernetes.io/name"
	relayLabel     = "spo-relay"
	// graceMargin is what the pod's grace period must leave beyond the relay's
	// teardown bound: the stores' close and the process's exit.
	graceMargin = 10
)

// tree is the manifest directory in memory: path (slash-separated, relative)
// to content. The checks read it only, so a test can mutate a copy.
type tree map[string]string

func loadTree(t *testing.T) tree {
	t.Helper()
	if _, err := os.Stat(manifestDir); err != nil {
		t.Skipf("the manifests are not in this source tree (%v); the Nix build copies spo/ only", err)
	}
	tr := tree{}
	err := filepath.WalkDir(manifestDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(manifestDir, p)
		tr[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func (tr tree) copy() tree {
	c := tree{}
	for k, v := range tr {
		c[k] = v
	}
	return c
}

func (tr tree) paths() []string {
	out := make([]string, 0, len(tr))
	for p := range tr {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// doc is one decoded YAML document.
type doc struct {
	file string
	m    map[string]any
}

func (d doc) kind() string { return str(d.m["kind"]) }
func (d doc) name() string { return str(get(d.m, "metadata", "name")) }

// The value helpers return the zero value for a missing or mistyped field.
func get(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func str(v any) string        { s, _ := v.(string); return s }
func seq(v any) []any         { s, _ := v.([]any); return s }
func mp(v any) map[string]any { m, _ := v.(map[string]any); return m }
func num(v any) (int64, bool) { n, ok := v.(int64); return n, ok }

// decodeAll decodes every .yaml file of the tree.
func (tr tree) decodeAll() ([]doc, []string) {
	var docs []doc
	var bad []string
	for _, p := range tr.paths() {
		if !strings.HasSuffix(p, ".yaml") {
			continue
		}
		ds, err := decodeYAML(tr[p])
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		for _, m := range ds {
			docs = append(docs, doc{p, m})
		}
	}
	return docs, bad
}

// layout is what the kustomizations say about the files: which are resources,
// which are patches, and the relay instances (a kustomization that builds one
// relay StatefulSet, directly or from base/instance).
type layout struct {
	resources map[string]bool // files listed as resources, with the files of listed directories
	patches   map[string]bool
	instances []instance
}

type instance struct {
	dir         string // the kustomization's directory
	suffix      string
	secret      string // the key Secret's name after its patches
	config      string // the relay.toml of its configMapGenerator
	statefulSet doc
}

func kustomization(tr tree, dir string) (map[string]any, error) {
	p := path.Join(dir, "kustomization.yaml")
	src, ok := tr[p]
	if !ok {
		return nil, fmt.Errorf("%s: no kustomization.yaml", dir)
	}
	ds, err := decodeYAML(src)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", p, err)
	}
	if len(ds) != 1 || str(ds[0]["kind"]) != "Kustomization" {
		return nil, fmt.Errorf("%s: not one Kustomization", p)
	}
	return ds[0], nil
}

// readLayout follows every kustomization of the tree.
func (tr tree) readLayout() (*layout, []string) {
	l := &layout{resources: map[string]bool{}, patches: map[string]bool{}}
	var bad []string
	var dirs []string
	for _, p := range tr.paths() {
		if path.Base(p) == "kustomization.yaml" {
			dirs = append(dirs, path.Dir(p))
		}
	}
	for _, dir := range dirs {
		k, err := kustomization(tr, dir)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		for key := range k {
			switch key {
			case "apiVersion", "kind", "resources", "patches", "configMapGenerator", "generatorOptions", "nameSuffix", "labels", "images":
			default:
				bad = append(bad, fmt.Sprintf("%s: the kustomization field %q is not used by these manifests", dir, key))
			}
		}
		for _, r := range seq(k["resources"]) {
			rp := path.Clean(path.Join(dir, str(r)))
			if _, isFile := tr[rp]; isFile {
				l.resources[rp] = true
			} else if _, isDir := tr[path.Join(rp, "kustomization.yaml")]; !isDir {
				bad = append(bad, fmt.Sprintf("%s: the resource %q is neither a file nor a kustomization", dir, str(r)))
			}
		}
		for _, pt := range seq(k["patches"]) {
			pp := path.Clean(path.Join(dir, str(get(pt, "path"))))
			if _, ok := tr[pp]; !ok {
				bad = append(bad, fmt.Sprintf("%s: the patch %q is missing", dir, str(get(pt, "path"))))
			}
			l.patches[pp] = true
		}
	}
	// the instances: a kustomization with a relay.toml generator
	for _, dir := range dirs {
		k, err := kustomization(tr, dir)
		if err != nil {
			continue
		}
		gens := seq(k["configMapGenerator"])
		if len(gens) == 0 {
			continue
		}
		in := instance{dir: dir, suffix: str(k["nameSuffix"])}
		for _, g := range gens {
			for _, f := range seq(get(g, "files")) {
				in.config = path.Clean(path.Join(dir, str(f)))
			}
		}
		// the StatefulSet: in this directory, or in the one resource it builds on
		sts := findStatefulSet(tr, dir)
		if sts.m == nil {
			bad = append(bad, fmt.Sprintf("%s: a relay configuration without a relay StatefulSet", dir))
			continue
		}
		in.statefulSet = sts
		in.secret = secretOf(sts.m)
		for _, pt := range seq(k["patches"]) {
			pp := path.Clean(path.Join(dir, str(get(pt, "path"))))
			ds, err := decodeYAML(tr[pp])
			if err != nil || len(ds) != 1 {
				continue
			}
			if s := secretOf(ds[0]); s != "" {
				in.secret = s
			}
		}
		l.instances = append(l.instances, in)
	}
	return l, bad
}

// findStatefulSet is the relay StatefulSet a kustomization builds: one of its
// resource files, or that of a kustomization it lists.
func findStatefulSet(tr tree, dir string) doc {
	k, err := kustomization(tr, dir)
	if err != nil {
		return doc{}
	}
	for _, r := range seq(k["resources"]) {
		rp := path.Clean(path.Join(dir, str(r)))
		if src, isFile := tr[rp]; isFile {
			ds, err := decodeYAML(src)
			if err != nil {
				continue
			}
			for _, m := range ds {
				if str(m["kind"]) == "StatefulSet" {
					return doc{rp, m}
				}
			}
			continue
		}
		if d := findStatefulSet(tr, rp); d.m != nil {
			return d
		}
	}
	return doc{}
}

// secretOf is the secretName of the relay-key volume of a StatefulSet (or of a
// patch of one).
func secretOf(m map[string]any) string {
	for _, v := range seq(get(m, "spec", "template", "spec", "volumes")) {
		if s := str(get(v, "secret", "secretName")); s != "" {
			return s
		}
	}
	return ""
}

// workloads are the full StatefulSets (resources, not patches).
func workloads(docs []doc, l *layout) []doc {
	var out []doc
	for _, d := range docs {
		if d.kind() == "StatefulSet" && l.resources[d.file] {
			out = append(out, d)
		}
	}
	return out
}

func podSpec(d doc) map[string]any { return mp(get(d.m, "spec", "template", "spec")) }

// containers are the init containers and the containers, with a label.
func containers(ps map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, f := range []string{"initContainers", "containers"} {
		for _, c := range seq(ps[f]) {
			out[f+"/"+str(get(c, "name"))] = mp(c)
		}
	}
	return out
}

func container(ps map[string]any, name string) map[string]any {
	for _, c := range seq(ps["containers"]) {
		if str(get(c, "name")) == name {
			return mp(c)
		}
	}
	return nil
}

// relayContainer is the container that runs spo-relay serve.
func relayContainer(ps map[string]any) map[string]any {
	for _, c := range seq(ps["containers"]) {
		if a := seq(get(c, "args")); len(a) > 0 && str(a[0]) == "serve" {
			return mp(c)
		}
	}
	return nil
}

func volume(ps map[string]any, name string) map[string]any {
	for _, v := range seq(ps["volumes"]) {
		if str(get(v, "name")) == name {
			return mp(v)
		}
	}
	return nil
}

// mountOf is the mount of the named volume in a container.
func mountOf(c map[string]any, vol string) map[string]any {
	for _, m := range seq(c["volumeMounts"]) {
		if str(get(m, "name")) == vol {
			return mp(m)
		}
	}
	return nil
}

// check is one property of the manifests; it returns what is wrong.
type check func(tr tree) []string

var checks = map[string]check{
	"parse":          checkParse,
	"namespace":      checkNamespace,
	"pod-security":   checkPodSecurity,
	"no-secrets":     checkNoSecrets,
	"images":         checkImages,
	"relay-config":   checkRelayConfig,
	"mounts":         checkMounts,
	"grace":          checkGrace,
	"one-relay":      checkOneRelayPerKey,
	"network-policy": checkNetworkPolicy,
	"probes":         checkProbes,
	"disruption":     checkDisruption,
	"resources":      checkResources,
	"containerfile":  checkContainerfile,
	"patches":        checkPatches,
}

// TestTheManifests runs every check on the manifests as they are.
//
// spec: SPO-Xmailbox-SEC-077, SPO-Xmailbox-PRE-063, SPO-Xmailbox-OUT-101, SPO-Xmailbox-OUT-102
func TestTheManifests(t *testing.T) {
	tr := loadTree(t)
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			for _, p := range checks[n](tr) {
				t.Error(p)
			}
		})
	}
}

var allowedKinds = map[string]bool{
	"Kustomization": true, "Namespace": true, "ServiceAccount": true, "StatefulSet": true,
	"NetworkPolicy": true, "PodDisruptionBudget": true,
}

// checkParse: every file decodes, is a known kind, and is plain manifests (no
// Helm, no custom resource, no Service: the relay takes no inbound connection).
func checkParse(tr tree) []string {
	docs, bad := tr.decodeAll()
	_, lbad := tr.readLayout()
	bad = append(bad, lbad...)
	for _, d := range docs {
		if !allowedKinds[d.kind()] {
			bad = append(bad, fmt.Sprintf("%s: the kind %q is not one of the relay's", d.file, d.kind()))
		}
		if d.kind() != "Kustomization" && (str(d.m["apiVersion"]) == "" || d.name() == "") {
			bad = append(bad, fmt.Sprintf("%s: a %s without apiVersion or name", d.file, d.kind()))
		}
	}
	for _, p := range tr.paths() {
		switch {
		case strings.Contains(tr[p], "{{"):
			bad = append(bad, fmt.Sprintf("%s: a template expression", p))
		case path.Base(p) == "Chart.yaml":
			bad = append(bad, fmt.Sprintf("%s: a Helm chart", p))
		case strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".json"):
			bad = append(bad, fmt.Sprintf("%s: write manifests as .yaml", p))
		}
	}
	return bad
}

// checkNamespace: one Namespace that enforces the restricted Pod Security
// Standard, and every other object in it.
func checkNamespace(tr tree) []string {
	docs, bad := tr.decodeAll()
	l, _ := tr.readLayout()
	seen := false
	for _, d := range docs {
		switch d.kind() {
		case "Namespace":
			seen = seen || d.name() == relayNamespace
			labels := mp(get(d.m, "metadata", "labels"))
			if str(labels["pod-security.kubernetes.io/enforce"]) != "restricted" {
				bad = append(bad, fmt.Sprintf("%s: the namespace does not enforce the restricted Pod Security Standard", d.file))
			}
		case "Kustomization":
		default:
			if l.resources[d.file] || l.patches[d.file] {
				if ns := str(get(d.m, "metadata", "namespace")); ns != relayNamespace {
					bad = append(bad, fmt.Sprintf("%s: %s %s is in namespace %q, not %q", d.file, d.kind(), d.name(), ns, relayNamespace))
				}
			}
		}
	}
	if !seen {
		bad = append(bad, "no Namespace "+relayNamespace)
	}
	return bad
}

// checkPodSecurity: the restricted Pod Security Standard and more, for every
// workload and every container in it.
func checkPodSecurity(tr tree) []string {
	docs, bad := tr.decodeAll()
	l, _ := tr.readLayout()
	sas := map[string]map[string]any{}
	for _, d := range docs {
		if d.kind() == "ServiceAccount" {
			sas[d.name()] = d.m
		}
	}
	ws := workloads(docs, l)
	if len(ws) == 0 {
		bad = append(bad, "no workload")
	}
	for _, d := range ws {
		at := d.file + ": " + d.name()
		ps := podSpec(d)
		if ps["automountServiceAccountToken"] != false {
			bad = append(bad, at+": the pod mounts a service account token")
		}
		sa := sas[str(ps["serviceAccountName"])]
		if sa == nil {
			bad = append(bad, at+": the service account is not one of these manifests")
		} else if sa["automountServiceAccountToken"] != false {
			bad = append(bad, at+": the service account mounts its token")
		}
		if ps["enableServiceLinks"] != false {
			bad = append(bad, at+": service links are on")
		}
		for _, h := range []string{"hostNetwork", "hostPID", "hostIPC", "hostUsers", "shareProcessNamespace"} {
			if ps[h] == true {
				bad = append(bad, at+": "+h)
			}
		}
		sc := mp(ps["securityContext"])
		if sc["runAsNonRoot"] != true {
			bad = append(bad, at+": the pod does not require a non-root user")
		}
		for _, f := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
			if n, ok := num(sc[f]); !ok || n != relayUID {
				bad = append(bad, fmt.Sprintf("%s: the pod's %s is %v, not %d", at, f, sc[f], relayUID))
			}
		}
		if str(sc["fsGroupChangePolicy"]) != "OnRootMismatch" {
			bad = append(bad, at+": fsGroupChangePolicy is not OnRootMismatch (a recursive change adds group bits to the stores' 0600 files and 0700 directories, which the stores refuse)")
		}
		if str(get(sc, "seccompProfile", "type")) != "RuntimeDefault" {
			bad = append(bad, at+": the pod's seccomp profile is not RuntimeDefault")
		}
		if len(seq(sc["sysctls"])) > 0 || sc["seLinuxOptions"] != nil || sc["windowsOptions"] != nil {
			bad = append(bad, at+": sysctls or SELinux or Windows options in the pod's security context")
		}
		for _, v := range seq(ps["volumes"]) {
			ok := false
			for _, kind := range []string{"configMap", "secret", "emptyDir", "persistentVolumeClaim", "projected", "downwardAPI"} {
				if mp(v)[kind] != nil {
					ok = true
				}
			}
			if !ok {
				bad = append(bad, fmt.Sprintf("%s: the volume %q is of a kind the restricted standard does not allow", at, str(get(v, "name"))))
			}
		}
		cs := containers(ps)
		if len(seq(ps["ephemeralContainers"])) > 0 {
			bad = append(bad, at+": ephemeral containers in the manifest")
		}
		for name, c := range cs {
			cat := at + ": " + name
			csc := mp(c["securityContext"])
			if csc["allowPrivilegeEscalation"] != false {
				bad = append(bad, cat+": privilege escalation is not off")
			}
			if csc["readOnlyRootFilesystem"] != true {
				bad = append(bad, cat+": the root file system is writable")
			}
			if csc["privileged"] == true {
				bad = append(bad, cat+": privileged")
			}
			if csc["runAsNonRoot"] == false || csc["runAsUser"] != nil && csc["runAsUser"] != int64(relayUID) {
				bad = append(bad, cat+": the container overrides the pod's user")
			}
			drop := seq(get(csc, "capabilities", "drop"))
			if len(drop) != 1 || str(drop[0]) != "ALL" {
				bad = append(bad, cat+": not all capabilities are dropped")
			}
			if len(seq(get(csc, "capabilities", "add"))) > 0 {
				bad = append(bad, cat+": a capability is added")
			}
			if p := str(get(csc, "seccompProfile", "type")); p != "" && p != "RuntimeDefault" {
				bad = append(bad, cat+": the container's seccomp profile is "+p)
			}
			if csc["procMount"] != nil || csc["seLinuxOptions"] != nil {
				bad = append(bad, cat+": procMount or SELinux options")
			}
			for _, p := range seq(c["ports"]) {
				if get(p, "hostPort") != nil {
					bad = append(bad, cat+": a host port")
				}
			}
			if len(seq(c["ports"])) > 0 {
				bad = append(bad, cat+": a container port (the relay listens on no pod port; the tunnel is outbound)")
			}
		}
	}
	return bad
}

var (
	secretPatterns = map[string]*regexp.Regexp{
		"an AWS access key id":      regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
		"an AWS secret key setting": regexp.MustCompile(`(?i)aws_secret_access_key|aws_session_token|secretAccessKey`),
		"a private key block":       regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		"a relay key file":          regexp.MustCompile(`spo-relay-key-v1|(?m)^\s*(node|psk) [0-9a-f]{64}\s*$`),
		"a pre-shared key":          regexp.MustCompile(`(?i)\bpsk\b\s*[:=]\s*"?[0-9a-f]{16,}`),
		"a token":                   regexp.MustCompile(`(?i)\b(token|password|passwd|secret_key|api_key)\s*[:=]\s*"?[A-Za-z0-9+/_\-]{12,}`),
		"a Vault token":             regexp.MustCompile(`\bhvs\.[A-Za-z0-9_\-]{20,}`),
		"the address flag":          regexp.MustCompile(`--print-address`),
		"a tailcat address":         regexp.MustCompile(`(?i)\btailcat://`),
	}
)

// checkNoSecrets: no Secret object, no data in a manifest, no literal key or
// credential anywhere in the directory, and never --print-address (whatever a
// pod prints goes to its log, and the address holds the pre-shared key).
func checkNoSecrets(tr tree) []string {
	docs, bad := tr.decodeAll()
	for _, d := range docs {
		if d.kind() == "Secret" || d.m["data"] != nil || d.m["stringData"] != nil || d.m["binaryData"] != nil {
			bad = append(bad, fmt.Sprintf("%s: a Secret or literal data in a manifest", d.file))
		}
		k := d.kind()
		if k == "Kustomization" {
			if d.m["secretGenerator"] != nil {
				bad = append(bad, d.file+": a secretGenerator")
			}
			for _, g := range seq(d.m["configMapGenerator"]) {
				if get(g, "literals") != nil || get(g, "envs") != nil {
					bad = append(bad, d.file+": a configMapGenerator with literals or envs")
				}
			}
		}
		for _, c := range containers(podSpec(d)) {
			for _, e := range seq(c["env"]) {
				n := strings.ToUpper(str(get(e, "name")))
				for _, w := range []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AWS_", "VAULT_"} {
					if strings.Contains(n, w) {
						bad = append(bad, fmt.Sprintf("%s: the environment variable %s", d.file, n))
					}
				}
			}
			if len(seq(c["envFrom"])) > 0 {
				bad = append(bad, d.file+": envFrom")
			}
		}
	}
	for _, p := range tr.paths() {
		for what, re := range secretPatterns {
			if re.MatchString(tr[p]) {
				bad = append(bad, fmt.Sprintf("%s: %s", p, what))
			}
		}
	}
	return bad
}

// An image is pinned by digest; a digest still to be filled is written
// sha256:FILL_IN_..., which no registry resolves, so an unfilled manifest fails
// at the pull and never runs something unpinned.
var (
	pinnedRE = regexp.MustCompile(`^[a-z0-9.\-]+(:[0-9]+)?(/[a-z0-9._\-]+)+(:[A-Za-z0-9._\-]+)?@sha256:([0-9a-f]{64}|FILL_IN_[A-Z_]+)$`)
	latestRE = regexp.MustCompile(`(?i):latest\b`)
)

// checkImages: every image of a workload and every base of the Containerfile
// is pinned by digest, and nothing names a latest tag.
func checkImages(tr tree) []string {
	docs, bad := tr.decodeAll()
	for _, d := range docs {
		for name, c := range containers(podSpec(d)) {
			if img := str(c["image"]); !pinnedRE.MatchString(img) {
				bad = append(bad, fmt.Sprintf("%s: %s: the image %q is not pinned by digest", d.file, name, img))
			}
			if c["imagePullPolicy"] != nil && str(c["imagePullPolicy"]) != "IfNotPresent" {
				bad = append(bad, fmt.Sprintf("%s: %s: imagePullPolicy %v", d.file, name, c["imagePullPolicy"]))
			}
		}
		if d.kind() == "Kustomization" && len(seq(d.m["images"])) > 0 {
			bad = append(bad, d.file+": an images transformer (pin the image in the StatefulSet, where the checks see it)")
		}
	}
	for _, p := range tr.paths() {
		for _, line := range strings.Split(tr[p], "\n") {
			if latestRE.MatchString(line) && !strings.Contains(line, "pod-security.kubernetes.io/") {
				bad = append(bad, p+": a latest tag: "+strings.TrimSpace(line))
			}
		}
	}
	src, ok := tr["Containerfile"]
	if !ok {
		return append(bad, "no Containerfile")
	}
	froms := 0
	for _, line := range strings.Split(src, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], "FROM") {
			froms++
			if !pinnedRE.MatchString(f[1]) {
				bad = append(bad, fmt.Sprintf("Containerfile: the base %q is not pinned by digest", f[1]))
			}
		}
		if len(f) >= 1 && strings.EqualFold(f[0], "ARG") {
			bad = append(bad, "Containerfile: an ARG (a build argument can replace a pinned base)")
		}
	}
	if froms == 0 {
		bad = append(bad, "Containerfile: no FROM")
	}
	return bad
}
