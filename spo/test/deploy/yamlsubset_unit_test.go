package deploy

import (
	"reflect"
	"testing"
)

func TestTheYAMLSubsetDecodesWhatTheManifestsUse(t *testing.T) {
	src := `# a comment
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spo-relay # trailing comment
  labels:
    app.kubernetes.io/name: "spo-relay"
spec:
  replicas: 1
  list:
  - a
  - b
  nested:
    - name: x
      value: '0440 # not a comment'
    - name: w
      args: ["serve", "--config", "/etc/x"]
    -
      name: z
  command:
    - /bin/sh
    - "-c"
    - |
      set -eu
      true
  empty: {}
  none: []
  flag: false
  size: 128Mi
  script: |
    set -eu
    install -d -m 0700 /data/state

  stripped: |-
    one
    two
---
kind: Second
`
	docs, err := decodeYAML(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[1]["kind"] != "Second" {
		t.Fatalf("documents: %v", docs)
	}
	want := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata": map[string]any{
			"name":   "spo-relay",
			"labels": map[string]any{"app.kubernetes.io/name": "spo-relay"},
		},
		"spec": map[string]any{
			"replicas": int64(1),
			"list":     []any{"a", "b"},
			"nested": []any{
				map[string]any{"name": "x", "value": "0440 # not a comment"},
				map[string]any{"name": "w", "args": []any{"serve", "--config", "/etc/x"}},
				map[string]any{"name": "z"},
			},
			"command":  []any{"/bin/sh", "-c", "set -eu\ntrue\n"},
			"empty":    map[string]any{},
			"none":     []any{},
			"flag":     false,
			"size":     "128Mi",
			"script":   "set -eu\ninstall -d -m 0700 /data/state\n",
			"stripped": "one\ntwo",
		},
	}
	if !reflect.DeepEqual(docs[0], want) {
		t.Fatalf("decoded\n%#v\nwant\n%#v", docs[0], want)
	}
}

// Every construct outside the subset is refused, in particular those that YAML
// 1.1 (kubectl, kustomize) and YAML 1.2 read differently.
func TestTheYAMLSubsetRefusesWhatItCannotReadExactly(t *testing.T) {
	for name, src := range map[string]string{
		"tab":               "a:\n\tb: 1\n",
		"octal":             "mode: 0440\n",
		"0o octal":          "mode: 0o440\n",
		"hex":               "mode: 0x1f\n",
		"float":             "x: 1.5\n",
		"exponent":          "x: 1e3\n",
		"sexagesimal":       "x: 1:20\n",
		"date":              "x: 2026-11-19\n",
		"yes":               "x: yes\n",
		"On":                "x: On\n",
		"True":              "x: True\n",
		"null word":         "x: null\n",
		"tilde":             "x: ~\n",
		"empty value":       "x:\ny: 1\n",
		"anchor":            "x: &a 1\n",
		"alias":             "x: *a\n",
		"tag":               "x: !!str 1\n",
		"folded":            "x: >\n  a\n",
		"flow mapping":      "x: {a: 1}\n",
		"nested flow":       "x: [[1]]\n",
		"duplicate key":     "x: 1\nx: 2\n",
		"question key":      "? x\n",
		"directive":         "%YAML 1.2\n---\nx: 1\n",
		"dash plain":        "x: -c\n",
		"colon plain":       "x: a: b\n",
		"bad escape":        "x: \"a\\n\"\n",
		"over-indented":     "a:\n  b: 1\n    c: 2\n",
		"top-level list":    "- a\n",
		"double space dash": "a:\n  -  b\n",
		"carriage return":   "a: 1\r\n",
	} {
		if _, err := decodeYAML(src); err == nil {
			t.Errorf("%s: %q was decoded", name, src)
		}
	}
}
