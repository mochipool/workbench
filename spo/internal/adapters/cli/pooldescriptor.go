package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The pool descriptor commands edit `<pool>.pool.json`, the file 05a reads.
// The domain Descriptor can parse and validate a descriptor but has no
// constructor and no setter, so this file builds and edits it as an ordered
// list of fields and parses the result through pool.ParseDescriptor: the
// domain check (Check) applies to what is written.

// placeholder marks a template value the operator must replace.
const placeholder = "CHANGE-ME"

// operatorFields are the fields of SPO-Pfiles-OUT-017 the operator edits, in
// the order of the template. The scripts write every other field.
var operatorFields = []string{
	pool.FieldName, pool.FieldOwner, pool.FieldRewards, pool.FieldPledge, pool.FieldCost, pool.FieldMargin, pool.FieldRelays,
	pool.FieldMetaName, pool.FieldMetaDesc, pool.FieldMetaTicker, pool.FieldMetaHomepage, pool.FieldMetaURL, pool.FieldExtendedURL,
}

// editableFields are the operator fields `descriptor set` changes. The name
// is the pool's and is not edited.
var editableFields = operatorFields[1:]

// marker is the line the template ends its operator part with.
const marker = "---"
const markerText = "DO NOT EDIT OR DELETE BELOW THIS LINE"

type field struct {
	key string
	val json.RawMessage
}

func marshalNoEscape(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// fieldsOf reads a descriptor's rendering back as ordered fields.
func fieldsOf(d *pool.Descriptor) ([]field, error) {
	dec := json.NewDecoder(bytes.NewReader(d.Render()))
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var out []field
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out = append(out, field{kt.(string), v})
	}
	return out, nil
}

// descriptorOf parses ordered fields through the domain type, which also
// normalises the rendering.
func descriptorOf(fs []field) (*pool.Descriptor, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range fs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(marshalNoEscape(f.key))
		b.WriteByte(':')
		b.Write(f.val)
	}
	b.WriteByte('}')
	return pool.ParseDescriptor(b.Bytes())
}

// withField returns the fields with key set: in place when it exists, else
// before the marker line, else last.
func withField(fs []field, key string, val json.RawMessage) []field {
	for i := range fs {
		if fs[i].key == key {
			out := append([]field(nil), fs...)
			out[i].val = val
			return out
		}
	}
	for i := range fs {
		if fs[i].key == marker {
			out := append([]field(nil), fs[:i]...)
			out = append(out, field{key, val})
			return append(out, fs[i:]...)
		}
	}
	return append(append([]field(nil), fs...), field{key, val})
}

func plainName(kind, s string) error {
	if s == "" || strings.ContainsAny(s, "/\\:, ") {
		return fmt.Errorf("%s %q must be a plain name (no directory part, colon, comma or space)", kind, s)
	}
	return nil
}

func urlField(name, v string, empty bool) error {
	if v == "" && empty {
		return nil
	}
	if !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") {
		return fmt.Errorf("%s must be an http(s) URL", name)
	}
	if utf8.RuneCountInString(v) > pool.MaxMetaURL {
		return fmt.Errorf("%s is longer than %d characters", name, pool.MaxMetaURL)
	}
	return nil
}

// parseOwners reads `NAME[:WITNESS],...`; the witness is "local" unless
// another word is given, conventionally "external" (SPO-05a-OUT-005).
func parseOwners(v string) (json.RawMessage, error) {
	type owner struct {
		Name    string `json:"ownerName"`
		Witness string `json:"ownerWitness"`
	}
	var out []owner
	seen := map[string]bool{}
	for _, e := range strings.Split(v, ",") {
		name, wit, _ := strings.Cut(strings.TrimSpace(e), ":")
		if err := plainName("an owner name", name); err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("the owner %q is listed twice", name)
		}
		seen[name] = true
		if wit == "" {
			wit = "local"
		}
		if err := plainName("an owner witness", wit); err != nil {
			return nil, err
		}
		out = append(out, owner{name, wit})
	}
	return marshalNoEscape(out), nil
}

// parseRelay reads `TYPE:ENTRY:PORT`. The entry may itself hold colons (an
// IPv6 address): the type is up to the first colon, the port after the last.
// SRV relays carry no port: `SRV:ENTRY`.
func parseRelay(v string) (pool.DescriptorRelay, error) {
	t, rest, ok := strings.Cut(strings.TrimSpace(v), ":")
	if !ok || t == "" || rest == "" {
		return pool.DescriptorRelay{}, fmt.Errorf("a relay is TYPE:ENTRY:PORT (SRV: TYPE:ENTRY), got %q", v)
	}
	r := pool.DescriptorRelay{Type: t, Entry: rest}
	if u := strings.ToUpper(t); u != "SRV" && u != "MULTISRV" {
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return pool.DescriptorRelay{}, fmt.Errorf("a %s relay needs a port: %s:ENTRY:PORT", t, t)
		}
		r.Entry, r.Port = rest[:i], rest[i+1:]
	}
	if _, err := pool.ParseRelay(r); err != nil {
		return pool.DescriptorRelay{}, err
	}
	return r, nil
}

func relaysJSON(rs []pool.DescriptorRelay) (json.RawMessage, error) {
	var parsed []pool.Relay
	type relay struct {
		Type  string `json:"relayType"`
		Entry string `json:"relayEntry"`
		Port  string `json:"relayPort"`
	}
	var out []relay
	for _, r := range rs {
		p, err := pool.ParseRelay(r)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, p)
		out = append(out, relay{r.Type, r.Entry, r.Port})
	}
	if err := pool.CheckRelays(parsed); err != nil {
		return nil, err
	}
	return marshalNoEscape(out), nil
}

func parseRelays(v string) (json.RawMessage, error) {
	var rs []pool.DescriptorRelay
	for _, e := range strings.Split(v, ",") {
		r, err := parseRelay(e)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	return relaysJSON(rs)
}

// fieldValue validates one operator field and returns its JSON value.
func fieldValue(key, v string) (json.RawMessage, error) {
	switch key {
	case pool.FieldOwner:
		return parseOwners(v)
	case pool.FieldRelays:
		return parseRelays(v)
	case pool.FieldRewards:
		if err := plainName("the reward account", v); err != nil {
			return nil, err
		}
	case pool.FieldPledge, pool.FieldCost:
		if _, err := pool.ParseLovelace(v); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
	case pool.FieldMargin:
		if _, err := pool.ParseMargin(v); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
	case pool.FieldMetaName:
		if n := utf8.RuneCountInString(v); n == 0 || n > pool.MaxMetaName {
			return nil, fmt.Errorf("%s must be 1 to %d characters", key, pool.MaxMetaName)
		}
	case pool.FieldMetaDesc:
		if n := utf8.RuneCountInString(v); n == 0 || n > pool.MaxMetaDescription {
			return nil, fmt.Errorf("%s must be 1 to %d characters", key, pool.MaxMetaDescription)
		}
	case pool.FieldMetaTicker:
		if n := utf8.RuneCountInString(v); n < 3 || n > 5 || pool.SanitizeTicker(v) != v {
			return nil, fmt.Errorf("%s must be 3 to 5 letters or digits", key)
		}
	case pool.FieldMetaHomepage, pool.FieldMetaURL:
		if err := urlField(key, v, false); err != nil {
			return nil, err
		}
	case pool.FieldExtendedURL:
		if err := urlField(key, v, true); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%q is not a field you set; the operator fields are: %s", key, strings.Join(editableFields, ", "))
	}
	return marshalNoEscape(v), nil
}

// template is the descriptor SPO-05a-IF-003 writes: the placeholders of the
// operator fields and the marker line.
func template(name string) []field {
	s := func(v string) json.RawMessage { return marshalNoEscape(v) }
	return []field{
		{pool.FieldName, s(name)},
		{pool.FieldOwner, marshalNoEscape([]map[string]string{{"ownerName": placeholder + "-owner", "ownerWitness": "local"}})},
		{pool.FieldRewards, s(placeholder + "-reward")},
		{pool.FieldPledge, s("100000000000")},
		{pool.FieldCost, s("10000000000")},
		{pool.FieldMargin, s("0.10")},
		{pool.FieldRelays, marshalNoEscape([]map[string]string{{"relayType": "DNS", "relayEntry": "relay." + placeholder + ".example", "relayPort": "3001"}})},
		{pool.FieldMetaName, s(placeholder + " pool name")},
		{pool.FieldMetaDesc, s(placeholder + " pool description")},
		{pool.FieldMetaTicker, s(placeholder)},
		{pool.FieldMetaHomepage, s("https://" + placeholder + ".example/")},
		{pool.FieldMetaURL, s("https://" + placeholder + ".example/" + name + ".metadata.json")},
		{pool.FieldExtendedURL, s("")},
		{marker, s(markerText)},
	}
}

// placeholderFields names the operator fields that still hold a template
// placeholder.
func placeholderFields(d *pool.Descriptor) []string {
	fs, err := fieldsOf(d)
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range fs {
		for _, k := range operatorFields {
			if f.key == k && bytes.Contains(f.val, []byte(placeholder)) {
				out = append(out, k)
			}
		}
	}
	return out
}

// validateWhole runs the domain check on a descriptor with no placeholder
// left. The minimum pool cost is a chain parameter, so it is not checked here
// (certificate generation does).
func validateWhole(d *pool.Descriptor) error {
	if len(placeholderFields(d)) > 0 {
		return nil
	}
	_, err := d.Check(0, pool.Choices{})
	return err
}

func poolArg(s string) (string, error) {
	s = strings.TrimPrefix(s, "./")
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".json"), ".pool")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("the pool name must be a plain name without a directory part: %q", s)
	}
	return s, nil
}

var errNoDescriptor = errors.New("there is no pool descriptor: create it with `spo pool descriptor new <pool>`")

func readDescriptorOf(ctx context.Context, store ports.Store, name string) (*pool.Descriptor, error) {
	var d *pool.Descriptor
	err := store.View(ctx, func(r ports.Reader) error {
		b, err := r.Get(ports.Ref{Name: name, Kind: ports.PoolDescriptor})
		if errors.Is(err, ports.ErrNotFound) {
			return fmt.Errorf("%w (pool %s)", errNoDescriptor, name)
		}
		if err != nil {
			return err
		}
		d, err = pool.ParseDescriptor(b)
		return err
	})
	return d, err
}

type descriptorNew struct {
	owners, relays                      []string
	reward, pledge, cost, margin        string
	metaName, metaDesc, metaTicker      string
	metaHomepage, metaURL, extendedMeta string
}

func (a *app) poolDescriptorCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "descriptor", Short: "The pool descriptor (<pool>.pool.json): new, show, set"}
	var f descriptorNew
	newCmd := &cobra.Command{
		Use:   "new <pool>",
		Short: "Write a template pool descriptor into the workspace",
		Long: `Write <pool>.pool.json with the operator fields of the upstream template, filled
from the flags. A field you do not give keeps a CHANGE-ME placeholder (owner, reward
account, relay, metadata) or the template default (pledge, cost, margin); the output
lists both. Certificate generation refuses a descriptor that still holds a placeholder.

--owner is NAME or NAME:WITNESS (repeatable). The witness is "local" (this machine
signs) unless another word is given, conventionally "external": the owner's stake key
then signs elsewhere and its slot stays open until its witness is imported.
--relay is TYPE:ENTRY:PORT (repeatable); TYPE is IP, IP6, DNS or SRV (SRV has no port).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{}, func(ctx context.Context, s *session, _ *Env, _ WireOptions) error {
				name, err := poolArg(args[0])
				if err != nil {
					return err
				}
				fs := template(name)
				var defaulted []string
				set := func(key, v string) error {
					val, err := fieldValue(key, v)
					if err != nil {
						return err
					}
					fs = withField(fs, key, val)
					return nil
				}
				if len(f.owners) > 0 {
					if err := set(pool.FieldOwner, strings.Join(f.owners, ",")); err != nil {
						return err
					}
				}
				if len(f.relays) > 0 {
					if err := set(pool.FieldRelays, strings.Join(f.relays, ",")); err != nil {
						return err
					}
				}
				for _, e := range []struct{ key, v string }{
					{pool.FieldRewards, f.reward}, {pool.FieldPledge, f.pledge}, {pool.FieldCost, f.cost}, {pool.FieldMargin, f.margin},
					{pool.FieldMetaName, f.metaName}, {pool.FieldMetaDesc, f.metaDesc}, {pool.FieldMetaTicker, f.metaTicker},
					{pool.FieldMetaHomepage, f.metaHomepage}, {pool.FieldMetaURL, f.metaURL}, {pool.FieldExtendedURL, f.extendedMeta},
				} {
					switch {
					case e.v != "" || (e.key == pool.FieldExtendedURL && cmd.Flags().Changed("extended-meta-url")):
						if err := set(e.key, e.v); err != nil {
							return err
						}
					case e.key == pool.FieldPledge || e.key == pool.FieldCost || e.key == pool.FieldMargin:
						defaulted = append(defaulted, e.key)
					}
				}
				d, err := descriptorOf(fs)
				if err != nil {
					return err
				}
				if err := validateWhole(d); err != nil {
					return err
				}
				ref := ports.Ref{Name: name, Kind: ports.PoolDescriptor}
				if err := s.Store.Update(ctx, func(w ports.Writer) error {
					if ok, err := w.Exists(ref); err != nil {
						return err
					} else if ok {
						return fmt.Errorf("the descriptor of pool %s already exists: change it with `spo pool descriptor set`; nothing was written", name)
					}
					return w.Put(ref, d.Render())
				}); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Stored %s.pool.json.\n", name)
				if ph := placeholderFields(d); len(ph) > 0 {
					fmt.Fprintf(a.d.Out, "Still placeholders (replace with `spo pool descriptor set %s KEY=VALUE`): %s\n", name, strings.Join(ph, ", "))
				}
				if len(defaulted) > 0 {
					fmt.Fprintf(a.d.Out, "Template defaults, check them: %s\n", strings.Join(defaulted, ", "))
				}
				return nil
			})
		},
	}
	fl := newCmd.Flags()
	fl.StringArrayVar(&f.owners, "owner", nil, "owner stake account NAME or NAME:WITNESS, witness \"local\" or \"external\" (repeatable)")
	fl.StringVar(&f.reward, "reward", "", "name of the reward account")
	fl.StringVar(&f.pledge, "pledge", "", "pledge, in lovelace")
	fl.StringVar(&f.cost, "cost", "", "fixed cost per epoch, in lovelace")
	fl.StringVar(&f.margin, "margin", "", "margin, a decimal from 0.00 to 1.00")
	fl.StringArrayVar(&f.relays, "relay", nil, "relay TYPE:ENTRY:PORT (repeatable)")
	fl.StringVar(&f.metaName, "meta-name", "", "metadata name (at most 50 characters)")
	fl.StringVar(&f.metaDesc, "meta-description", "", "metadata description (at most 255 characters)")
	fl.StringVar(&f.metaTicker, "meta-ticker", "", "metadata ticker (3 to 5 letters or digits)")
	fl.StringVar(&f.metaHomepage, "meta-homepage", "", "metadata homepage URL")
	fl.StringVar(&f.metaURL, "meta-url", "", "URL where <pool>.metadata.json will be published (at most 128 characters)")
	fl.StringVar(&f.extendedMeta, "extended-meta-url", "", "URL of the extended metadata (empty for none)")

	show := &cobra.Command{
		Use:   "show <pool>",
		Short: "Print the pool descriptor (without the registration protection key)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{}, func(ctx context.Context, s *session, _ *Env, _ WireOptions) error {
				name, err := poolArg(args[0])
				if err != nil {
					return err
				}
				d, err := readDescriptorOf(ctx, s.Store, name)
				if err != nil {
					return err
				}
				fs, err := fieldsOf(d)
				if err != nil {
					return err
				}
				var keep []field
				hidden := false
				for _, f := range fs {
					if f.key == pool.FieldRegProtection {
						hidden = true
						continue
					}
					keep = append(keep, f)
				}
				out, err := descriptorOf(keep)
				if err != nil {
					return err
				}
				a.d.Out.Write(out.Render())
				a.printPoolPending(ctx, a.d.Err, s, name)
				if hidden {
					fmt.Fprintf(a.d.Err, "%s is set and is not shown.\n", pool.FieldRegProtection)
				}
				return nil
			})
		},
	}

	setCmd := &cobra.Command{
		Use:   "set <pool> KEY=VALUE...",
		Short: "Change operator fields of the pool descriptor",
		Long: `Change operator fields: ` + strings.Join(editableFields, ", ") + `.
Each value is validated as certificate generation would. poolOwner takes
NAME[:WITNESS],... and poolRelays takes TYPE:ENTRY:PORT,... (comma separated).
Fields the scripts write (ids, hashes, certificate and registration records) are
refused, and so is any change while a witness collection is open.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{}, func(ctx context.Context, s *session, _ *Env, _ WireOptions) error {
				name, err := poolArg(args[0])
				if err != nil {
					return err
				}
				var certMade bool
				err = s.Store.Update(ctx, func(w ports.Writer) error {
					ref := ports.Ref{Name: name, Kind: ports.PoolDescriptor}
					b, err := w.Get(ref)
					if errors.Is(err, ports.ErrNotFound) {
						return fmt.Errorf("%w (pool %s)", errNoDescriptor, name)
					}
					if err != nil {
						return err
					}
					d, err := pool.ParseDescriptor(b)
					if err != nil {
						return err
					}
					if d.Has(pool.FieldRegWitness) {
						return errors.New("a witness collection is open for this pool: its transaction is fixed, so the descriptor is not changed now; nothing was written")
					}
					fs, err := fieldsOf(d)
					if err != nil {
						return err
					}
					for _, kv := range args[1:] {
						key, v, ok := strings.Cut(kv, "=")
						if !ok {
							return fmt.Errorf("%q is not KEY=VALUE", kv)
						}
						val, err := fieldValue(key, v)
						if err != nil {
							return err
						}
						fs = withField(fs, key, val)
					}
					nd, err := descriptorOf(fs)
					if err != nil {
						return err
					}
					if err := validateWhole(nd); err != nil {
						return err
					}
					certMade = nd.Has(pool.FieldRegCertFile)
					return w.Put(ref, nd.Render())
				})
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Updated %s.pool.json.\n", name)
				if certMade {
					fmt.Fprintf(a.d.Out, "The certificate was generated before this change: run `spo pool cert generate %s` again, or it still carries the old values.\n", name)
				}
				return nil
			})
		},
	}
	cmd.AddCommand(newCmd, show, setCmd)
	return cmd
}
