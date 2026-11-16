package pool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The pool descriptor `<pool>.pool.json` (SPO-Pfiles-OUT-017, the schema
// table of spec/upstream/scripts/05a). The file is edited by the operator
// and extended by the scripts, so the aggregate keeps every key it was read
// with, in order, and writes back exactly those it changes. The typed values
// the use cases compute with come from Check.

// DescriptorOwner is an entry of `poolOwner`.
type DescriptorOwner struct {
	Name string
	// Witness is `ownerWitness`: "local", empty (both mean this machine
	// signs) or any other word, conventionally "external" (SPO-05a-OUT-005).
	Witness string
}

// IsLocal reports whether this machine signs for the owner: "local" in any
// case, or empty (SPO-05c-INV-005).
func (o DescriptorOwner) IsLocal() bool {
	return o.Witness == "" || strings.EqualFold(o.Witness, "local")
}

// DescriptorRelay is an entry of `poolRelays`, as typed.
type DescriptorRelay struct{ Type, Entry, Port string }

// Descriptor is a parsed `<pool>.pool.json`.
type Descriptor struct{ doc *odoc }

// ErrBadDescriptor: the file is not a JSON object.
var ErrBadDescriptor = errors.New("the pool descriptor is not a valid JSON object")

// ParseDescriptor reads a descriptor.
//
// spec: SPO-05a-PRE-001
func ParseDescriptor(b []byte) (*Descriptor, error) {
	doc, err := parseODoc(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadDescriptor, err)
	}
	return &Descriptor{doc: doc}, nil
}

// Clone returns an independent copy.
func (d *Descriptor) Clone() *Descriptor { return &Descriptor{doc: d.doc.clone()} }

// Render writes the descriptor as upstream's `jq` rewrites do.
func (d *Descriptor) Render() []byte { return d.doc.renderJQ() }

// Text reads a field as `jq -r` prints it.
func (d *Descriptor) Text(key string) string { v, _ := d.doc.text(key); return v }

// Has reports a field that exists, is not null and is not the empty string
// (`readJSONparam` accepts it).
func (d *Descriptor) Has(key string) bool {
	raw, ok := d.doc.vals[key]
	if !ok {
		return false
	}
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && string(raw) != "null" && string(raw) != `""`
}

// Fields of the descriptor, as the scripts name them.
const (
	FieldName          = "poolName"
	FieldOwner         = "poolOwner"
	FieldRewards       = "poolRewards"
	FieldPledge        = "poolPledge"
	FieldCost          = "poolCost"
	FieldMargin        = "poolMargin"
	FieldRelays        = "poolRelays"
	FieldMetaName      = "poolMetaName"
	FieldMetaDesc      = "poolMetaDescription"
	FieldMetaTicker    = "poolMetaTicker"
	FieldMetaHomepage  = "poolMetaHomepage"
	FieldMetaURL       = "poolMetaUrl"
	FieldExtendedURL   = "poolExtendedMetaUrl"
	FieldPoolID        = "poolID"
	FieldPoolIDBech    = "poolIDbech"
	FieldMetaHash      = "poolMetaHash"
	FieldRegCertCreate = "regCertCreated"
	FieldRegCertFile   = "regCertFile"
	FieldRegProtection = "regProtectionKey"
	FieldRegEpoch      = "regEpoch"
	FieldRegSubmitted  = "regSubmitted"
	FieldRegWitness    = "regWitness"
	FieldDeregCreated  = "deregCertCreated"
	FieldDeregFile     = "deregCertFile"
	FieldDeregEpoch    = "deregEpoch"
	FieldDeregSubmit   = "deregSubmitted"
)

// ErrMissingField: a required field is absent, null or empty.
var ErrMissingField = errors.New("the pool descriptor lacks a required field")

// Require refuses a descriptor that lacks one of the fields, naming the
// first.
//
// spec: SPO-05a-IN-001, SPO-05c-IN-001, SPO-07b-IN-001
func (d *Descriptor) Require(fields ...string) error {
	for _, f := range fields {
		if !d.Has(f) {
			return fmt.Errorf("%w: %s", ErrMissingField, f)
		}
	}
	return nil
}

// Owners reads `poolOwner`: an array of {ownerName, ownerWitness} or, in
// the legacy format, a single string (SPO-05a-IN-002). legacy reports the
// string form.
func (d *Descriptor) Owners() (owners []DescriptorOwner, legacy bool, err error) {
	raw, ok := d.doc.vals[FieldOwner]
	if !ok {
		return nil, false, fmt.Errorf("%w: %s", ErrMissingField, FieldOwner)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		_ = json.Unmarshal(raw, &s)
		if s == "" {
			return nil, true, fmt.Errorf("%w: %s", ErrMissingField, FieldOwner)
		}
		return []DescriptorOwner{{Name: s}}, true, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return nil, false, fmt.Errorf("%w: %s must be a non-empty array", ErrMissingField, FieldOwner)
	}
	for i, e := range arr {
		o, err := parseODoc(e)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %s[%d] is not an object", ErrMissingField, FieldOwner, i)
		}
		name, ok := o.text("ownerName")
		if !ok || name == "" {
			return nil, false, fmt.Errorf("%w: %s[%d].ownerName", ErrMissingField, FieldOwner, i)
		}
		w, _ := o.text("ownerWitness")
		owners = append(owners, DescriptorOwner{Name: name, Witness: w})
	}
	return owners, false, nil
}

// Relays reads `poolRelays`.
func (d *Descriptor) Relays() ([]DescriptorRelay, error) {
	raw, ok := d.doc.vals[FieldRelays]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return nil, fmt.Errorf("%w: %s", ErrMissingField, FieldRelays)
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("%w: %s must be an array", ErrBadRelay, FieldRelays)
	}
	var out []DescriptorRelay
	for _, e := range arr {
		o, err := parseODoc(e)
		if err != nil {
			return nil, fmt.Errorf("%w: a relay is not an object", ErrBadRelay)
		}
		t, _ := o.text("relayType")
		en, _ := o.text("relayEntry")
		p, _ := o.text("relayPort")
		out = append(out, DescriptorRelay{Type: t, Entry: en, Port: p})
	}
	return out, nil
}

// ---- 05a: validation -------------------------------------------------------

// Refusals of the generation (05a).
var (
	// ErrNameMismatch: `poolName` differs from the normalised argument.
	ErrNameMismatch = errors.New("poolName in the descriptor differs from the pool name given (was the pool imported from another path?)")
	// ErrCostBelowMinimum: poolCost is below minPoolCost and the operator did
	// not accept raising it.
	ErrCostBelowMinimum = errors.New("poolCost is below the minimum pool cost of the protocol parameters")
	// ErrTickerCorrection: the ticker had characters outside letters and
	// digits and the operator did not accept the corrected ticker.
	ErrTickerCorrection = errors.New("poolMetaTicker contains characters that are not allowed; accept the corrected ticker or edit the descriptor")
	// ErrMetadataLimit: a metadata field is over its limit.
	ErrMetadataLimit = errors.New("a pool metadata field exceeds its limit")
)

// CostBelowMinimumError and TickerCorrectionError carry the figures a caller
// asks the operator about (SPO-05a-PR-001, SPO-05a-PR-002) before it runs
// again with the choice made.
type CostBelowMinimumError struct{ Cost, Min chain.Lovelace }

func (e *CostBelowMinimumError) Error() string {
	return fmt.Sprintf("%v: %d, minimum %d", ErrCostBelowMinimum, e.Cost, e.Min)
}
func (e *CostBelowMinimumError) Unwrap() error { return ErrCostBelowMinimum }

// TickerCorrectionError: see ErrTickerCorrection.
type TickerCorrectionError struct{ From, To string }

func (e *TickerCorrectionError) Error() string {
	return fmt.Sprintf("%v: %q would become %q", ErrTickerCorrection, e.From, e.To)
}
func (e *TickerCorrectionError) Unwrap() error { return ErrTickerCorrection }

// Limits of the metadata fields.
const (
	MaxMetaName        = 50
	MaxMetaDescription = 255
	MaxMetaURL         = 128
	MaxMetadataBytes   = 512
	// extendedURLBelow: extended metadata is produced only for a URL
	// shorter than this (SPO-05a-INV-003).
	extendedURLBelow = 65
)

// Choices are the answers to upstream's two prompts, given up front. Both
// default to No, as the prompts do.
type Choices struct {
	// RaiseCost accepts raising poolCost to minPoolCost (SPO-05a-PR-001).
	RaiseCost bool
	// AcceptTicker accepts the sanitised ticker (SPO-05a-PR-002).
	AcceptTicker bool
}

// Registration is a descriptor checked for certificate generation: the typed
// values, the descriptor updates the checks imply, and what to tell the
// operator.
type Registration struct {
	Name    string
	Owners  []DescriptorOwner
	Legacy  bool // poolOwner was a string
	Rewards string
	Pledge  chain.Lovelace
	Cost    chain.Lovelace
	Margin  chain.Rational
	Relays  []Relay
	Meta    Metadata
	MetaURL string
	// Corrections are the descriptor fields the checks rewrite, in order:
	// poolCost, poolMetaTicker (SPO-05a-OUT-002, SPO-05a-PR-002).
	Corrections []Correction
	// ExtendedURL is set when extended metadata applies (SPO-05a-INV-003);
	// Warnings lists what upstream passes over silently.
	ExtendedURL string
	Warnings    []string
}

// Correction is one descriptor field rewritten by a check.
type Correction struct{ Field, Value string }

// CheckName compares the descriptor's name with the normalised argument.
//
// spec: SPO-05a-PRE-002
func (d *Descriptor) CheckName(arg string) error {
	if d.Text(FieldName) != arg {
		return fmt.Errorf("%w: %q and %q", ErrNameMismatch, d.Text(FieldName), arg)
	}
	return nil
}

// Check validates the descriptor for generation, in upstream's order, and
// returns the typed result. It changes nothing: the corrections are in the
// result and Apply writes them.
//
// spec: SPO-05a-IN-001, SPO-05a-PRE-004, SPO-05a-PRE-005, SPO-05a-PRE-006, SPO-05a-PRE-007, SPO-05a-PRE-008,
// spec: SPO-05a-PRE-009, SPO-05a-PRE-010, SPO-05a-PR-001, SPO-05a-PR-002, SPO-05a-INV-002, SPO-05a-INV-003,
// spec: SPO-05a-OUT-002, SPO-05a-OUT-004, SPO-05a-OUT-005
func (d *Descriptor) Check(minPoolCost chain.Lovelace, c Choices) (Registration, error) {
	var r Registration
	if err := d.Require(FieldName, FieldOwner, FieldRewards, FieldPledge, FieldCost, FieldMargin, FieldRelays,
		FieldMetaName, FieldMetaTicker, FieldMetaHomepage, FieldMetaURL, FieldMetaDesc); err != nil {
		return r, err
	}
	var err error
	r.Name, r.Rewards = d.Text(FieldName), d.Text(FieldRewards)
	if r.Owners, r.Legacy, err = d.Owners(); err != nil {
		return r, err
	}
	if r.Pledge, err = ParseLovelace(d.Text(FieldPledge)); err != nil {
		return r, fmt.Errorf("poolPledge: %w", err)
	}
	if r.Cost, err = ParseLovelace(d.Text(FieldCost)); err != nil {
		// Bash reads a non-numeric cost as 0, which counts as too low.
		return r, fmt.Errorf("poolCost: %w", err)
	}
	if r.Cost < minPoolCost {
		if !c.RaiseCost {
			return r, &CostBelowMinimumError{Cost: r.Cost, Min: minPoolCost}
		}
		r.Cost = minPoolCost
		r.Corrections = append(r.Corrections, Correction{FieldCost, utoa(uint64(minPoolCost))})
	}
	if r.Margin, err = ParseMargin(d.Text(FieldMargin)); err != nil {
		return r, err
	}
	rels, err := d.Relays()
	if err != nil {
		return r, err
	}
	for i, dr := range rels {
		rel, err := ParseRelay(dr)
		if err != nil {
			return r, fmt.Errorf("relay %d: %w", i+1, err)
		}
		r.Relays = append(r.Relays, rel)
	}
	if err := CheckRelays(r.Relays); err != nil {
		return r, err
	}

	name := d.Text(FieldMetaName)
	if utf8.RuneCountInString(name) > MaxMetaName {
		return r, fmt.Errorf("%w: poolMetaName is longer than %d characters", ErrMetadataLimit, MaxMetaName)
	}
	orig := d.Text(FieldMetaTicker)
	ticker := SanitizeTicker(orig)
	if n := utf8.RuneCountInString(ticker); n < 3 || n > 5 {
		return r, fmt.Errorf("%w: poolMetaTicker must be 3 to 5 characters", ErrMetadataLimit)
	}
	if ticker != orig {
		if !c.AcceptTicker {
			return r, &TickerCorrectionError{From: orig, To: ticker}
		}
		r.Corrections = append(r.Corrections, Correction{FieldMetaTicker, ticker})
	}
	home, url := d.Text(FieldMetaHomepage), d.Text(FieldMetaURL)
	if !hasHTTP(home) || utf8.RuneCountInString(home) > MaxMetaURL {
		return r, fmt.Errorf("%w: poolMetaHomepage is not an http(s) URL of at most %d characters", ErrMetadataLimit, MaxMetaURL)
	}
	if !hasHTTP(url) || utf8.RuneCountInString(url) > MaxMetaURL {
		return r, fmt.Errorf("%w: poolMetaUrl is not an http(s) URL of at most %d characters", ErrMetadataLimit, MaxMetaURL)
	}
	desc := d.Text(FieldMetaDesc)
	if utf8.RuneCountInString(desc) > MaxMetaDescription {
		return r, fmt.Errorf("%w: poolMetaDescription is longer than %d characters", ErrMetadataLimit, MaxMetaDescription)
	}
	r.MetaURL = url
	r.Meta = Metadata{Name: name, Description: desc, Ticker: ticker, Homepage: home}

	ext := d.Text(FieldExtendedURL)
	if utf8.RuneCountInString(ext) > MaxMetaURL {
		return r, fmt.Errorf("%w: poolExtendedMetaUrl is longer than %d characters", ErrMetadataLimit, MaxMetaURL)
	}
	if hasHTTP(ext) {
		if utf8.RuneCountInString(ext) < extendedURLBelow {
			r.ExtendedURL = ext
		} else {
			r.Warnings = append(r.Warnings, fmt.Sprintf("poolExtendedMetaUrl is %d characters: extended metadata is produced only below %d, so none is", utf8.RuneCountInString(ext), extendedURLBelow))
		}
	}
	return r, nil
}

func hasHTTP(s string) bool { return strings.Contains(s, "http://") || strings.Contains(s, "https://") }

// SanitizeTicker replaces every character that is not a letter or a digit
// with `_`. Upstream's classification follows the shell's locale; the port
// uses Unicode letters and digits.
//
// spec: SPO-05a-PRE-010
func SanitizeTicker(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return '_'
	}, s)
}

// Apply writes the corrections into the descriptor.
func (d *Descriptor) Apply(cs []Correction) {
	for _, c := range cs {
		d.doc.setAny(c.Field, c.Value)
	}
}

// NormalizeOwners rewrites a legacy string `poolOwner` as an array and gives
// every owner without `ownerWitness` the value "local".
//
// spec: SPO-05a-OUT-004, SPO-05a-OUT-005
func (d *Descriptor) NormalizeOwners(owners []DescriptorOwner) {
	type ow struct {
		Name    string `json:"ownerName"`
		Witness string `json:"ownerWitness,omitempty"`
	}
	raw := d.doc.vals[FieldOwner]
	trim := bytes.TrimSpace(raw)
	if len(trim) > 0 && trim[0] == '"' {
		d.doc.setAny(FieldOwner, []ow{{Name: owners[0].Name, Witness: "local"}})
		return
	}
	var arr []json.RawMessage
	_ = json.Unmarshal(raw, &arr)
	out := make([]json.RawMessage, len(arr))
	for i, e := range arr {
		o, _ := parseODoc(e)
		if _, ok := o.text("ownerWitness"); !ok {
			o.setAny("ownerWitness", "local")
		}
		out[i] = bytes.TrimRight(o.renderCompact(), "\n")
	}
	d.doc.setAny(FieldOwner, out)
}

func (o *odoc) renderCompact() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := marshalNoEscape(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

// RecordGeneration writes the values 05a derives, in the order it writes
// them: the ids, the metadata hash, then the certificate record and the
// protection key (SPO-05a-OUT-001, OUT-008, OUT-011, OUT-012).
func (d *Descriptor) RecordGeneration(poolID, poolIDBech, metaHash, created, certFile, protectionKey string) {
	d.doc.setAny(FieldPoolID, poolID)
	d.doc.setAny(FieldPoolIDBech, poolIDBech)
	d.doc.setAny(FieldMetaHash, metaHash)
	d.doc.setAny(FieldRegCertCreate, created)
	d.doc.setAny(FieldRegCertFile, certFile)
	if protectionKey != "" {
		d.doc.setAny(FieldRegProtection, protectionKey)
	}
}

// RecordRetirementCert writes the retirement certificate record; other
// fields, including a previous deregSubmitted, stay (SPO-07a-OUT-002).
func (d *Descriptor) RecordRetirementCert(created, file string, epoch uint64) {
	d.doc.setAny(FieldDeregCreated, created)
	d.doc.setAny(FieldDeregFile, file)
	d.doc.setAny(FieldDeregEpoch, utoa(epoch))
}

// RecordSubmission writes the registration record: regEpoch and
// regSubmitted are set and the witness collection removed (SPO-05c-OUT-005).
func (d *Descriptor) RecordSubmission(epoch, when string) {
	d.doc.setAny(FieldRegEpoch, epoch)
	d.doc.setAny(FieldRegSubmitted, when)
	d.doc.del(FieldRegWitness)
}

// RecordRetirement writes deregSubmitted (SPO-07b-OUT-001, OUT-002).
func (d *Descriptor) RecordRetirement(when string) { d.doc.setAny(FieldDeregSubmit, when) }

// ---- metadata ------------------------------------------------------------

// Metadata is the published pool metadata (SPO-Pfiles-OUT-021).
type Metadata struct {
	Name, Description, Ticker, Homepage string
	// Extended is the URL of the extended metadata, empty for none.
	Extended string
}

// Render writes `<pool>.metadata.json` in upstream's layout: two-space
// indent, the keys in order, a trailing newline. Values are JSON-escaped;
// upstream interpolates them as text, which breaks on a quote or a
// backslash (SPO-05a-OUT-007).
//
// spec: SPO-05a-OUT-007
func (m Metadata) Render() []byte {
	var b bytes.Buffer
	b.WriteString("{\n  \"name\": " + quote(m.Name) + ",\n  \"description\": " + quote(m.Description) +
		",\n  \"ticker\": " + quote(m.Ticker) + ",\n  \"homepage\": " + quote(m.Homepage))
	if m.Extended != "" {
		b.WriteString(",\n  \"extended\": " + quote(m.Extended))
	}
	b.WriteString("\n}\n")
	return b.Bytes()
}

// CheckMetadataSize refuses a metadata file over the ledger's 512 bytes.
//
// spec: SPO-05a-PRE-012
func CheckMetadataSize(doc []byte) error {
	if len(doc) > MaxMetadataBytes {
		return fmt.Errorf("%w: the metadata file is %d bytes, the limit is %d", ErrMetadataLimit, len(doc), MaxMetadataBytes)
	}
	return nil
}

// MergeExtended renders `<pool>.extended-metadata.json`: the additional
// metadata, pretty-printed as `jq` does (the deep merge of upstream's `*`
// over an empty object). Invalid JSON is refused (SPO-05a-PRE-011).
//
// spec: SPO-05a-OUT-006, SPO-05a-PRE-011
func MergeExtended(additional []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(additional))
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("additional-metadata.json is not valid JSON: %w", err)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("additional-metadata.json is not a JSON object")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, bytes.TrimSpace(additional)); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// AdditionalMetadataTemplate is the dummy upstream writes when the operator
// has none (SPO-05a-OUT-003); the pool id fills two lists.
func AdditionalMetadataTemplate(poolIDHex string) []byte {
	return []byte("\n{\n  \"info\": {\n        \"url_png_icon_64x64\": \"http(s) url to pool icon\",\n        \"url_png_logo\": \"http(s) url to pool logo\",\n" +
		"        \"location\": \"Country, Continent\",\n        \"social\": {\n            \"twitter_handle\": \"\",\n            \"telegram_handle\": \"\",\n" +
		"            \"facebook_handle\": \"\",\n            \"youtube_handle\": \"\",\n            \"twitch_handle\": \"\",\n            \"discord_handle\": \"\",\n" +
		"\t    \"github_handle\": \"\"\n        },\n        \"company\": {\n            \"name\": \"\",\n            \"addr\": \"\",\n            \"city\": \"\",\n" +
		"            \"country\": \"\",\n            \"company_id\": \"\",\n            \"vat_id\": \"\"\n        },\n        \"about\": {\n            \"me\": \"\",\n" +
		"            \"server\": \"\",\n            \"company\": \"\"\n        },\n\t\"rss\": \"http(s) url to valid RSS feed\"\n    },\n\n" +
		"  \"telegram-admin-handle\": [\n        \"\"\n    ],\n\n  \"my-pool-ids\": [\n        \"" + poolIDHex + "\"\n    ],\n" +
		"  \"when-satured-then-recommend\": [\n        \"" + poolIDHex + "\"\n    ]\n}\n\n")
}
