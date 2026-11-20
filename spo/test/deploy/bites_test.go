package deploy

import (
	"strings"
	"testing"
)

// A mutation breaks one manifest; the named check must then report it. Each
// replaces the nth occurrence of old in file (old "" creates the file).
type mutation struct {
	check, file, old, new string
	nth                   int // 0 or 1: the first occurrence
}

const ss = "base/instance/statefulset.yaml"

var mutations = []mutation{
	// parse
	{check: "parse", file: ss, old: "kind: StatefulSet", new: "kind: Deployment"},
	{check: "parse", file: "base/shared/service.yaml", new: "apiVersion: v1\nkind: Service\nmetadata:\n  name: spo-relay\n  namespace: spo-relay\n"},
	{check: "parse", file: "base/shared/kustomization.yaml", old: "  - namespace.yaml", new: "  - namespace.yaml\n  - missing.yaml"},
	{check: "parse", file: "base/shared/namespace.yaml", old: "restricted\n", new: "{{ .Values.level }}\n"},
	// namespace
	{check: "namespace", file: "base/shared/namespace.yaml", old: "enforce: restricted", new: "enforce: baseline"},
	{check: "namespace", file: "base/shared/serviceaccount.yaml", old: "namespace: spo-relay", new: "namespace: default"},
	// pod-security
	{check: "pod-security", file: ss, old: "runAsNonRoot: true", new: "runAsNonRoot: false"},
	{check: "pod-security", file: ss, old: "runAsUser: 10001", new: "runAsUser: 0"},
	{check: "pod-security", file: ss, old: "fsGroupChangePolicy: OnRootMismatch", new: "fsGroupChangePolicy: Always"},
	{check: "pod-security", file: ss, old: "type: RuntimeDefault", new: "type: Unconfined"},
	{check: "pod-security", file: ss, old: "readOnlyRootFilesystem: true", new: "readOnlyRootFilesystem: false", nth: 1},
	{check: "pod-security", file: ss, old: "readOnlyRootFilesystem: true", new: "readOnlyRootFilesystem: false", nth: 2},
	{check: "pod-security", file: ss, old: "allowPrivilegeEscalation: false", new: "allowPrivilegeEscalation: true", nth: 2},
	{check: "pod-security", file: ss, old: "                - ALL", new: "                - NET_RAW", nth: 2},
	{check: "pod-security", file: ss, old: "              drop:\n                - ALL", new: "              add:\n                - NET_ADMIN\n              drop:\n                - ALL", nth: 1},
	{check: "pod-security", file: ss, old: "      automountServiceAccountToken: false", new: "      automountServiceAccountToken: true"},
	{check: "pod-security", file: "base/shared/serviceaccount.yaml", old: "automountServiceAccountToken: false", new: "automountServiceAccountToken: true"},
	{check: "pod-security", file: ss, old: "enableServiceLinks: false", new: "enableServiceLinks: true"},
	{check: "pod-security", file: ss, old: "hostNetwork: false", new: "hostNetwork: true"},
	{check: "pod-security", file: ss, old: "hostPID: false", new: "hostPID: true"},
	{check: "pod-security", file: ss, old: "          emptyDir:\n            sizeLimit: 16Mi", new: "          hostPath:\n            path: /tmp"},
	{check: "pod-security", file: ss, old: "          securityContext:\n            allowPrivilegeEscalation: false", new: "          securityContext:\n            privileged: true\n            allowPrivilegeEscalation: false", nth: 2},
	{check: "pod-security", file: ss, old: "          volumeMounts:\n            - name: config", new: "          ports:\n            - containerPort: 7346\n          volumeMounts:\n            - name: config"},
	// no-secrets
	{check: "no-secrets", file: "overlays/example/relay-a/secret.yaml", new: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: spo-relay-key-a\n  namespace: spo-relay\nstringData:\n  relay.key: x\n"},
	{check: "no-secrets", file: ss, old: "            - /etc/spo-relay/relay.toml", new: "            - /etc/spo-relay/relay.toml\n            - \"--print-address\""},
	{check: "no-secrets", file: ss, old: "            - name: GOMEMLIMIT", new: "            - name: AWS_ACCESS_KEY_ID\n              value: \"AKIAABCDEFGHIJKLMNOP\"\n            - name: GOMEMLIMIT"},
	{check: "no-secrets", file: "base/instance/relay.key", new: "spo-relay-key-v1\nnode " + strings.Repeat("ab", 32) + "\npsk " + strings.Repeat("cd", 32) + "\n"},
	{check: "no-secrets", file: "base/instance/kustomization.yaml", old: "generatorOptions:", new: "secretGenerator:\n  - name: k\n    files:\n      - relay.key\ngeneratorOptions:"},
	// images
	{check: "images", file: ss, old: "busybox:1.37@sha256:FILL_IN_DIGEST_OF_BUSYBOX", new: "busybox:1.37"},
	{check: "images", file: ss, old: "spo-relay:0.1.0@sha256:FILL_IN_DIGEST_OF_SPO_RELAY", new: "spo-relay:latest"},
	{check: "images", file: "Containerfile", old: "static-debian12@sha256:FILL_IN_DIGEST_OF_THE_RUNTIME_IMAGE", new: "static-debian12"},
	{check: "images", file: "Containerfile", old: "FROM docker.io", new: "ARG BASE\nFROM docker.io"},
	// relay-config
	{check: "relay-config", file: "base/instance/relay.toml", old: `admission    = "open"`, new: `admission    = "closed"`},
	{check: "relay-config", file: "overlays/example/relay-b/relay.toml", old: `node_key = "3333`, new: `node_key = "3G33`},
	{check: "relay-config", file: "overlays/example/relay-a/relay.toml", old: "registry_dir = \"/data/state/registry\"\n", new: "registry_dir = \"/data/state/registry\"\nunsafe_open_tunnel = true\n"},
	{check: "relay-config", file: "base/instance/relay.toml", old: `"/run/spo-relay/key/relay.key"`, new: `"/data/key/relay.key"`},
	{check: "relay-config", file: "base/instance/relay.toml", old: `"/data/state/mailbox"`, new: `"/data/mailbox"`},
	{check: "relay-config", file: "base/instance/kustomization.yaml", old: "disableNameSuffixHash: true", new: "disableNameSuffixHash: false"},
	{check: "relay-config", file: "overlays/example/relay-a/kustomization.yaml", old: "generatorOptions:\n  disableNameSuffixHash: true\n", new: ""},
	{check: "relay-config", file: ss, old: "              mountPath: /etc/spo-relay\n", new: "              mountPath: /etc/spo-relay\n              subPath: conf\n"},
	{check: "relay-config", file: ss, old: "            - /etc/spo-relay/relay.toml", new: "            - /etc/spo-relay/other.toml"},
	{check: "relay-config", file: ss, old: "install -m 0600", new: "install -m 0640"},
	{check: "relay-config", file: ss, old: "install -d -m 0700", new: "install -d -m 0750"},
	{check: "relay-config", file: ss, old: "              install -m 0600", new: "              chmod 0777 /data\n              install -m 0600"},
	{check: "relay-config", file: ss, old: "              mountPath: /run/spo-relay\n              readOnly: true", new: "              mountPath: /run/spo-relay"},
	{check: "relay-config", file: ss, old: "            medium: Memory\n", new: ""},
	// mounts: what the real Load, LoadKey and stores refuse
	{check: "mounts", file: ss, old: "defaultMode: 292", new: "defaultMode: 438"},
	{check: "mounts", file: ss, old: "        fsGroup: 10001\n", new: ""},
	{check: "mounts", file: ss, old: "install -m 0600", new: "install -m 0640"},
	{check: "mounts", file: ss, old: "install -d -m 0700", new: "install -d -m 0770"},
	{check: "mounts", file: "base/instance/relay.toml", old: `"/data/state/registry"`, new: `"/data/registry"`},
	// grace
	{check: "grace", file: ss, old: "terminationGracePeriodSeconds: 45", new: "terminationGracePeriodSeconds: 20"},
	{check: "grace", file: ss, old: "terminationGracePeriodSeconds: 45", new: "terminationGracePeriodSeconds: 29"},
	{check: "grace", file: ss, old: "          env:\n", new: "          lifecycle:\n            preStop:\n              exec:\n                command: [\"/x\"]\n          env:\n"},
	// one-relay
	{check: "one-relay", file: ss, old: "replicas: 1", new: "replicas: 2"},
	{check: "one-relay", file: "overlays/example/relay-b/key-secret.yaml", old: "spo-relay-key-b", new: "spo-relay-key-a"},
	{check: "one-relay", file: "overlays/example/relay-b/kustomization.yaml", old: `nameSuffix: "-b"`, new: `nameSuffix: "-a"`},
	{check: "one-relay", file: "overlays/example/relay-b/kustomization.yaml", old: "patches:\n  - path: key-secret.yaml\n", new: ""},
	{check: "one-relay", file: ss, old: "            - name: tmp\n              mountPath: /tmp", new: "            - name: tmp\n              mountPath: /tmp\n            - name: relay-key\n              mountPath: /secret"},
	{check: "one-relay", file: ss, old: "- ReadWriteOncePod", new: "- ReadWriteMany"},
	{check: "one-relay", file: ss, old: "whenDeleted: Retain", new: "whenDeleted: Delete"},
	{check: "one-relay", file: ss, old: "type: RollingUpdate", new: "type: OnDelete"},
	{check: "one-relay", file: ss, old: "podManagementPolicy: OrderedReady", new: "podManagementPolicy: Parallel"},
	{check: "one-relay", file: ss, old: "        - name: tmp\n          emptyDir:\n            sizeLimit: 16Mi", new: "        - name: tmp\n          persistentVolumeClaim:\n            claimName: shared"},
	// network-policy
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "  podSelector: {}\n", new: "  podSelector: {}\n  egress:\n    - {}\n"},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "    - Ingress\n    - Egress\n---", new: "    - Ingress\n---"},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "  egress:\n    - to:\n        - namespaceSelector:", new: "  ingress:\n    - {}\n  egress:\n    - to:\n        - namespaceSelector:"},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "              - \"169.254.0.0/16\"\n", new: ""},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "              - \"fc00::/7\"\n", new: ""},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "          port: 443", new: "          port: 22"},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "            cidr: \"0.0.0.0/0\"", new: "            cidr: \"10.0.0.0/8\""},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: kube-system\n          podSelector:\n            matchLabels:\n              k8s-app: kube-dns", new: "        - ipBlock:\n            cidr: \"0.0.0.0/0\""},
	{check: "network-policy", file: "base/shared/networkpolicy.yaml", old: "    - to:\n        - ipBlock:", new: "    - {}\n    - to:\n        - ipBlock:"},
	// probes
	{check: "probes", file: ss, old: "          env:\n", new: "          livenessProbe:\n            httpGet:\n              path: /healthz\n              port: 8080\n          env:\n"},
	{check: "probes", file: ss, old: "          env:\n", new: "          readinessProbe:\n            exec:\n              command: [\"/usr/local/bin/spo-relay\", \"check-config\"]\n          env:\n"},
	// disruption
	{check: "disruption", file: "base/shared/poddisruptionbudget.yaml", old: "maxUnavailable: 1", new: "maxUnavailable: 0"},
	{check: "disruption", file: "base/shared/poddisruptionbudget.yaml", old: "maxUnavailable: 1", new: "minAvailable: 1"},
	{check: "disruption", file: "base/shared/poddisruptionbudget.yaml", old: "      app.kubernetes.io/name: spo-relay", new: "      app.kubernetes.io/instance: spo-relay"},
	{check: "disruption", file: "base/shared/poddisruptionbudget.yaml", old: "spec:", new: "spec:\n  unhealthyPodEvictionPolicy: AlwaysAllow\n  maxUnavailable: 1\n  selector:\n    matchLabels:\n      app.kubernetes.io/name: spo-relay\n---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: second\n  namespace: spo-relay\nspec:"},
	// resources
	{check: "resources", file: ss, old: "              memory: 512Mi\n", new: ""},
	{check: "resources", file: ss, old: "              cpu: 10m\n", new: ""},
	{check: "resources", file: ss, old: "name: GOMEMLIMIT", new: "name: GOGC"},
	// containerfile
	{check: "containerfile", file: "Containerfile", old: "USER 10001:10001", new: "USER 0"},
	{check: "containerfile", file: "Containerfile", old: "gcr.io/distroless/static-debian12", new: "docker.io/library/debian"},
	{check: "containerfile", file: "Containerfile", old: "CGO_ENABLED=0 ", new: ""},
	{check: "containerfile", file: "Containerfile", old: "./cmd/spo-relay", new: "./cmd/spo"},
	// patches
	{check: "patches", file: "overlays/example/relay-a/key-secret.yaml", old: "      volumes:", new: "      hostNetwork: true\n      volumes:"},
	{check: "patches", file: "overlays/example/relay-b/key-secret.yaml", old: "            secretName: spo-relay-key-b", new: "            secretName: spo-relay-key-b\n            defaultMode: 511"},
}

// TestEveryCheckBites applies each mutation to a copy of the manifests and
// requires the named check to report it, and every check to have a mutation.
func TestEveryCheckBites(t *testing.T) {
	tr := loadTree(t)
	covered := map[string]bool{}
	for i, m := range mutations {
		c, ok := checks[m.check]
		if !ok {
			t.Fatalf("mutation %d names no check %q", i, m.check)
		}
		covered[m.check] = true
		mt := tr.copy()
		if m.old == "" {
			if _, exists := mt[m.file]; exists {
				t.Fatalf("mutation %d: %s exists", i, m.file)
			}
			mt[m.file] = m.new
		} else {
			src, ok := mt[m.file]
			nth := max(m.nth, 1)
			if !ok || strings.Count(src, m.old) < nth {
				t.Fatalf("mutation %d (%s): %q does not occur %d time(s) in %s; update the mutation with the manifest", i, m.check, m.old, nth, m.file)
			}
			at := -1
			for k := 0; k < nth; k++ {
				at += 1 + strings.Index(src[at+1:], m.old)
			}
			mt[m.file] = src[:at] + m.new + src[at+len(m.old):]
		}
		// a mutation bites for its own reason, not because the file stopped decoding
		if _, bad := mt.decodeAll(); m.check != "parse" && len(bad) > 0 {
			t.Fatalf("mutation %d (%s) does not decode: %v", i, m.check, bad)
		}
		got := c(mt)
		if len(got) == 0 {
			t.Errorf("mutation %d (%s): %s %q -> %q was not reported", i, m.check, m.file, m.old, m.new)
			continue
		}
		t.Logf("mutation %d (%s): %s", i, m.check, got[0])
	}
	for n := range checks {
		if !covered[n] {
			t.Errorf("the check %q has no mutation", n)
		}
	}
}
