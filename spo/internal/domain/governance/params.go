package governance

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The protocol parameters a ParameterChange action can update.
//
// Upstream's 25a takes 41 named parameters (SPO-25a-IF-021, SPO-25a-IF-022).
// They are listed in ParamSpecs with the type the spec gives each and the
// width of the ledger type it ends up in. Three more updatable groups that
// upstream's script does not offer but cardano-cli does are offered here as an
// extension: the execution-unit limits of a transaction and of a block, and
// the cost models. A parameter group of the ledger that is not in this list
// (there is none in Conway beyond those) is refused by name.

// ParamType is how a parameter value is written and checked.
type ParamType string

// Parameter types of SPO-25a-IF-022.
const (
	ParamLovelace ParamType = "LOVELACE"
	ParamNatural  ParamType = "NATURAL" // digits, not zero (upstream's rule)
	ParamWord32   ParamType = "WORD32"
	ParamWord16   ParamType = "WORD16"
	ParamInt      ParamType = "INT" // an integer the ledger holds in a word of Bits bits
	ParamRational ParamType = "RATIONAL"
	// Extension types.
	ParamUnits      ParamType = "UNITS"       // "(steps,memory)", as cardano-cli takes it
	ParamCostModels ParamType = "COST-MODELS" // JSON object of language name to integer array
)

// ParamSpec describes one parameter: its cardano-cli name, its type, the
// largest value an integer type may take and the names the same parameter has
// in a provider's parameters document (cardano-cli's and Koios's) so the
// summary can show the value it has now.
type ParamSpec struct {
	Name string
	Type ParamType
	// Max is the largest value of an integer type (the ledger's word); zero
	// means the type's own limit. For a rational it is the largest numerator
	// over denominator: zero means 1, the bound upstream applies to every
	// rational, except for UnboundedRational.
	Max uint64
	// UnboundedRational lifts the "at most 1.0" bound that upstream applies to
	// every rational (SPO-25a-IF-022 quirk); ref-script-cost-per-byte is 15 on
	// mainnet.
	UnboundedRational bool
	// Doc and EpochDoc are the JSON paths of the current value in a
	// `query protocol-parameters` document and in a Koios epoch_params row.
	Doc, EpochDoc []string
	// Group is the set the parameter is all-or-nothing with, empty for none.
	Group string
	// Extension marks the parameters upstream's script does not offer.
	Extension bool
}

// Group names. A group is given completely or not at all.
const (
	GroupPoolVoting  = "pool-voting-threshold"
	GroupDRepVoting  = "drep-voting-threshold"
	GroupExecPrices  = "price-execution"
	groupPoolMembers = 5
	groupDRepMembers = 10
)

func ps(name string, t ParamType, doc string, epoch string) ParamSpec {
	s := ParamSpec{Name: name, Type: t}
	if doc != "" {
		s.Doc = strings.Split(doc, ".")
	}
	if epoch != "" {
		s.EpochDoc = strings.Split(epoch, ".")
	}
	return s
}

func withMax(s ParamSpec, m uint64) ParamSpec { s.Max = m; return s }

func inGroup(s ParamSpec, g string) ParamSpec { s.Group = g; return s }

// Widths. The Conway CDDL (conway.cddl, protocol_param_update) types the
// integer parameters as: coin (a 64-bit lovelace amount; the bound here is the
// signed 63 bits, stricter) for the fees, deposits, minimum pool cost and
// utxo-cost-per-byte; `uint .size 4` (Word32) for the maximum block-body and
// transaction sizes, the maximum value size and the epoch intervals (pool
// retirement, committee term, action lifetime, DRep activity); `uint .size 2`
// (Word16) for the maximum block-header size, the target number of pools, the
// collateral percentage, the maximum number of collateral inputs and the
// minimum committee size. TestParamWidthsAreTheLedgers pins each one.

// ParamMax is the largest value of an integer parameter: the width of the
// ledger's type. It is false for a parameter that is not an integer.
func ParamMax(name string) (uint64, bool) {
	s, ok := specByName[strings.ToLower(name)]
	switch {
	case !ok:
		return 0, false
	case s.Type == ParamLovelace || s.Type == ParamNatural || s.Type == ParamWord32 || s.Type == ParamWord16 || s.Type == ParamInt:
		return intLimit(s), true
	}
	return 0, false
}

// ParamSpecs lists the parameters in the order of the ledger's update map.
var ParamSpecs = buildSpecs()

func buildSpecs() []ParamSpec {
	pool := func(n, doc string) ParamSpec {
		return inGroup(ps("pool-voting-threshold-"+n, ParamRational, "poolVotingThresholds."+doc, ""), GroupPoolVoting)
	}
	drep := func(n, doc string) ParamSpec {
		return inGroup(ps("drep-voting-threshold-"+n, ParamRational, "dRepVotingThresholds."+doc, ""), GroupDRepVoting)
	}
	ref := ps("ref-script-cost-per-byte", ParamRational, "minFeeRefScriptCostPerByte", "min_fee_ref_script_cost_per_byte")
	ref.UnboundedRational = true
	costModels := ps("cost-models", ParamCostModels, "costModels", "cost_models")
	costModels.Extension = true
	maxTx := ps("max-tx-execution-units", ParamUnits, "maxTxExecutionUnits", "")
	maxTx.Extension = true
	maxBlock := ps("max-block-execution-units", ParamUnits, "maxBlockExecutionUnits", "")
	maxBlock.Extension = true
	return []ParamSpec{
		ps("min-fee-linear", ParamLovelace, "txFeePerByte", "min_fee_a"),
		ps("min-fee-constant", ParamLovelace, "txFeeFixed", "min_fee_b"),
		ps("max-block-body-size", ParamWord32, "maxBlockBodySize", "max_block_size"),
		ps("max-tx-size", ParamWord32, "maxTxSize", "max_tx_size"),
		ps("max-block-header-size", ParamWord16, "maxBlockHeaderSize", "max_bh_size"),
		ps("key-reg-deposit-amt", ParamNatural, "stakeAddressDeposit", "key_deposit"),
		ps("pool-reg-deposit", ParamNatural, "stakePoolDeposit", "pool_deposit"),
		ps("pool-retirement-epoch-interval", ParamWord32, "poolRetireMaxEpoch", "max_epoch"),
		withMax(ps("number-of-pools", ParamNatural, "stakePoolTargetNum", "optimal_pool_count"), math.MaxUint16),
		ps("pool-influence", ParamRational, "poolPledgeInfluence", "influence"),
		ps("monetary-expansion", ParamRational, "monetaryExpansion", "monetary_expand_rate"),
		ps("treasury-expansion", ParamRational, "treasuryCut", "treasury_growth_rate"),
		ps("min-pool-cost", ParamNatural, "minPoolCost", "min_pool_cost"),
		ps("utxo-cost-per-byte", ParamLovelace, "utxoCostPerByte", "coins_per_utxo_size"),
		costModels,
		inGroup(ps("price-execution-memory", ParamRational, "executionUnitPrices.priceMemory", "price_mem"), GroupExecPrices),
		inGroup(ps("price-execution-steps", ParamRational, "executionUnitPrices.priceSteps", "price_step"), GroupExecPrices),
		maxTx,
		maxBlock,
		withMax(ps("max-value-size", ParamInt, "maxValueSize", "max_val_size"), math.MaxUint32),
		withMax(ps("collateral-percent", ParamInt, "collateralPercentage", "collateral_percent"), math.MaxUint16),
		withMax(ps("max-collateral-inputs", ParamInt, "maxCollateralInputs", "max_collateral_inputs"), math.MaxUint16),
		pool("motion-no-confidence", "motionNoConfidence"),
		pool("committee-normal", "committeeNormal"),
		pool("committee-no-confidence", "committeeNoConfidence"),
		pool("hard-fork-initiation", "hardForkInitiation"),
		pool("pp-security-group", "ppSecurityGroup"),
		drep("motion-no-confidence", "motionNoConfidence"),
		drep("committee-normal", "committeeNormal"),
		drep("committee-no-confidence", "committeeNoConfidence"),
		drep("update-to-constitution", "updateToConstitution"),
		drep("hard-fork-initiation", "hardForkInitiation"),
		drep("pp-network-group", "ppNetworkGroup"),
		drep("pp-economic-group", "ppEconomicGroup"),
		drep("pp-technical-group", "ppTechnicalGroup"),
		drep("pp-governance-group", "ppGovGroup"),
		drep("treasury-withdrawal", "treasuryWithdrawal"),
		withMax(ps("min-committee-size", ParamInt, "committeeMinSize", "committee_min_size"), math.MaxUint16),
		ps("committee-term-length", ParamWord32, "committeeMaxTermLength", "committee_max_term_length"),
		ps("governance-action-lifetime", ParamWord32, "govActionLifetime", "gov_action_lifetime"),
		ps("new-governance-action-deposit", ParamNatural, "govActionDeposit", "gov_action_deposit"),
		ps("drep-deposit", ParamLovelace, "dRepDeposit", "drep_deposit"),
		ps("drep-activity", ParamWord32, "dRepActivity", "drep_activity"),
		ref,
	}
}

var specByName = func() map[string]ParamSpec {
	m := map[string]ParamSpec{}
	for _, s := range ParamSpecs {
		m[s.Name] = s
	}
	return m
}()

// ParamSpecOf finds a parameter by its (lower-case) name.
func ParamSpecOf(name string) (ParamSpec, bool) { s, ok := specByName[name]; return s, ok }

// UpstreamParamCount is the number of parameters of upstream's table.
const UpstreamParamCount = 41

// ParamNames lists the names of the parameters, for a usage text.
func ParamNames() []string {
	out := make([]string, len(ParamSpecs))
	for i, s := range ParamSpecs {
		out[i] = s.Name
	}
	return out
}

// Refusals of a parameter set.
var ErrParam = fmt.Errorf("%w: protocol parameter", ErrActionField)

func paramErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrParam}, args...)...)
}

// NormalizeParam checks one `name`, `value` pair as given and returns it in
// canonical form: the name lower-cased, an integer in plain decimal, a
// rational reduced to `num/den`, units as `(steps,memory)` and cost models as
// compact JSON with the languages in order. The type and range are those of
// SPO-25a-IF-022 with the corrections of its port note: a rational is bounded
// by 1 except ref-script-cost-per-byte, and an integer by the ledger's word.
//
// spec: SPO-25a-IF-021, SPO-25a-IF-022
func NormalizeParam(name, value string) (ParamChange, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.TrimSpace(value)
	s, ok := specByName[name]
	if !ok {
		return ParamChange{}, paramErr("%q is not one of the supported parameters (%s)", name, strings.Join(ParamNames(), ", "))
	}
	bad := func(why string) (ParamChange, error) {
		return ParamChange{}, paramErr("%s = %q: %s", name, value, why)
	}
	switch s.Type {
	case ParamLovelace, ParamNatural, ParamWord32, ParamWord16, ParamInt:
		n, ok := parseDigits(value)
		if !ok {
			return bad("want digits only")
		}
		if s.Type == ParamNatural && n == 0 {
			return bad("must not be zero")
		}
		if n > intLimit(s) {
			return bad("is larger than the ledger's type of this parameter allows (" + strconv.FormatUint(intLimit(s), 10) + ")")
		}
		return ParamChange{Name: name, Value: strconv.FormatUint(n, 10)}, nil
	case ParamRational:
		r, err := ParseRational(value, s.UnboundedRational)
		if err != nil {
			return bad(err.Error())
		}
		return ParamChange{Name: name, Value: ratText(r)}, nil
	case ParamUnits:
		u, err := ParseUnits(value)
		if err != nil {
			return bad(err.Error())
		}
		return ParamChange{Name: name, Value: u.Text()}, nil
	case ParamCostModels:
		cm, err := ParseCostModels([]byte(value))
		if err != nil {
			return bad(err.Error())
		}
		return ParamChange{Name: name, Value: cm.Text()}, nil
	}
	return bad("unknown type")
}

func intLimit(s ParamSpec) uint64 {
	if s.Max != 0 {
		return s.Max
	}
	switch s.Type {
	case ParamWord32:
		return math.MaxUint32
	case ParamWord16:
		return math.MaxUint16
	}
	return math.MaxInt64
}

func parseDigits(s string) (uint64, bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// ParseRational reads a rational written as digits (`15`), a decimal (`0.0577`) or a
// fraction (`2/3`). Without unbounded it must be at most 1, the bound upstream
// applies to every rational. The result is reduced, as the ledger stores it.
//
// spec: SPO-25a-IF-022
func ParseRational(s string, unbounded bool) (chain.Rational, error) {
	if s == "" || strings.Trim(s, "0123456789./") != "" || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Count(s, "/") > 1 || strings.Count(s, ".") > 1 ||
		(strings.Contains(s, "/") && strings.Contains(s, ".")) {
		return chain.Rational{}, fmt.Errorf("want a fraction (2/3), a decimal (0.66) or an integer")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 || !r.Num().IsUint64() || !r.Denom().IsUint64() {
		return chain.Rational{}, fmt.Errorf("not a rational the ledger can hold")
	}
	if !unbounded && r.Cmp(big.NewRat(1, 1)) > 0 {
		return chain.Rational{}, fmt.Errorf("must not be greater than 1")
	}
	return chain.Rational{Num: r.Num().Uint64(), Den: r.Denom().Uint64()}, nil
}

func ratText(r chain.Rational) string { return fmt.Sprintf("%d/%d", r.Num, r.Den) }

// FormatRational writes a rational as an exact decimal when it has one (0.0577)
// and as `num/den` otherwise, the form the summary shows for old and new values
// alike.
func FormatRational(r chain.Rational) string {
	if r.Den == 0 {
		return "invalid"
	}
	d := r.Den
	twos, fives := 0, 0
	for d%2 == 0 {
		d /= 2
		twos++
	}
	for d%5 == 0 {
		d /= 5
		fives++
	}
	if d != 1 {
		return ratText(r)
	}
	scale := twos
	if fives > scale {
		scale = fives
	}
	x := new(big.Int).Mul(new(big.Int).SetUint64(r.Num), new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil))
	x.Div(x, new(big.Int).SetUint64(r.Den))
	digits := x.String()
	if scale == 0 {
		return digits
	}
	for len(digits) <= scale {
		digits = "0" + digits
	}
	out := digits[:len(digits)-scale] + "." + digits[len(digits)-scale:]
	return strings.TrimRight(out, "0")
}

// Units are execution units: memory and CPU steps.
type Units struct{ Memory, Steps uint64 }

// Text is `(steps,memory)`, the order cardano-cli takes.
func (u Units) Text() string { return fmt.Sprintf("(%d,%d)", u.Steps, u.Memory) }

// ParseUnits reads `(steps,memory)` (cardano-cli's order and spelling; the
// parentheses and spaces are optional).
func ParseUnits(s string) (Units, error) {
	t := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "("), ")")
	a, b, ok := strings.Cut(t, ",")
	steps, ok1 := parseDigits(strings.TrimSpace(a))
	mem, ok2 := parseDigits(strings.TrimSpace(b))
	if !ok || !ok1 || !ok2 {
		return Units{}, fmt.Errorf("want (steps,memory), two integers")
	}
	return Units{Memory: mem, Steps: steps}, nil
}

// CostModels are the cost-model arrays of the languages being updated, by
// language number (0 PlutusV1, 1 PlutusV2, 2 PlutusV3), in the file format
// cardano-cli reads: {"PlutusV1": [...], ...}.
type CostModels map[uint8][]int64

var languageNames = []string{"PlutusV1", "PlutusV2", "PlutusV3"}

// ParseCostModels reads the JSON object of a cost-model file.
func ParseCostModels(b []byte) (CostModels, error) {
	var raw map[string][]int64
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("want a JSON object {\"PlutusV1\": [...], ...} of integers: %v", err)
	}
	out := CostModels{}
	for name, arr := range raw {
		found := false
		for i, ln := range languageNames {
			if ln == name {
				out[uint8(i)], found = arr, true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown language %q (PlutusV1, PlutusV2, PlutusV3)", name)
		}
		if len(arr) == 0 {
			return nil, fmt.Errorf("the cost model of %s is empty", name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no cost model given")
	}
	return out, nil
}

// Text is the compact JSON of the models, languages in order.
func (c CostModels) Text() string {
	var parts []string
	for i, name := range languageNames {
		arr, ok := c[uint8(i)]
		if !ok {
			continue
		}
		b, _ := json.Marshal(arr)
		parts = append(parts, fmt.Sprintf("%q:%s", name, b))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ParseParamRational and the accessors below read a canonical ParamChange
// value back into its typed form; an action file's decoder and encoder use
// them, so a value is written exactly as it was validated.

// Uint is the value of an integer parameter.
func (p ParamChange) Uint() (uint64, error) {
	n, ok := parseDigits(p.Value)
	if !ok {
		return 0, paramErr("%s: %q is not an integer", p.Name, p.Value)
	}
	return n, nil
}

// Rational is the value of a rational parameter.
func (p ParamChange) Rational() (chain.Rational, error) {
	num, den, ok := strings.Cut(p.Value, "/")
	n, ok1 := parseDigits(num)
	d, ok2 := parseDigits(den)
	if !ok || !ok1 || !ok2 || d == 0 {
		return chain.Rational{}, paramErr("%s: %q is not a rational", p.Name, p.Value)
	}
	return chain.Rational{Num: n, Den: d}, nil
}

// Units is the value of an execution-units parameter.
func (p ParamChange) Units() (Units, error) { return ParseUnits(p.Value) }

// CostModels is the value of the cost-models parameter.
func (p ParamChange) CostModels() (CostModels, error) { return ParseCostModels([]byte(p.Value)) }

// CheckParams validates a whole parameter set: each pair, no name twice, at
// least one parameter, and the all-or-nothing groups. It returns the set in
// canonical form, in the order of ParamSpecs (the ledger's map order), whatever
// the order given: the order of an update is not meaningful.
//
// spec: SPO-25a-IF-021, SPO-25a-IF-022, SPO-25a-IF-023, SPO-25a-PRE-017
func CheckParams(in []ParamChange) ([]ParamChange, error) {
	if len(in) == 0 {
		return nil, paramErr("a parameter change needs at least one parameter")
	}
	seen := map[string]ParamChange{}
	for _, p := range in {
		n, err := NormalizeParam(p.Name, p.Value)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[n.Name]; dup {
			return nil, paramErr("%s is given twice", n.Name)
		}
		seen[n.Name] = n
	}
	for _, g := range []struct {
		name string
		n    int
	}{{GroupPoolVoting, groupPoolMembers}, {GroupDRepVoting, groupDRepMembers}, {GroupExecPrices, 2}} {
		have, all := 0, 0
		var missing []string
		for _, s := range ParamSpecs {
			if s.Group != g.name {
				continue
			}
			all++
			if _, ok := seen[s.Name]; ok {
				have++
			} else {
				missing = append(missing, s.Name)
			}
		}
		if all != g.n {
			return nil, paramErr("internal: group %s has %d members, not %d", g.name, all, g.n)
		}
		if have != 0 && have != all {
			return nil, paramErr("the %s parameters are given all or none: %s missing", g.name, strings.Join(missing, ", "))
		}
	}
	out := make([]ParamChange, 0, len(seen))
	for _, s := range ParamSpecs {
		if p, ok := seen[s.Name]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// SortParams returns the parameters in the order of ParamSpecs.
func SortParams(in []ParamChange) []ParamChange {
	by := map[string]ParamChange{}
	for _, p := range in {
		by[p.Name] = p
	}
	out := make([]ParamChange, 0, len(in))
	for _, s := range ParamSpecs {
		if p, ok := by[s.Name]; ok {
			out = append(out, p)
		}
	}
	return out
}

// ParamDiff is one changed parameter: the new value, the value the chain has
// now when a parameter document says it, and why it does not when it does not.
type ParamDiff struct {
	Name string
	New  string
	// Old is empty when unknown; Why then says why.
	Old string
	Why string
}

// Line is the summary line of the change.
func (d ParamDiff) Line() string {
	if d.Old == "" {
		return fmt.Sprintf("%s: now %s (current value unknown: %s)", d.Name, d.New, d.Why)
	}
	if d.Old == d.New {
		return fmt.Sprintf("%s: %s, unchanged", d.Name, d.New)
	}
	return fmt.Sprintf("%s: %s -> %s", d.Name, d.Old, d.New)
}

// DescribeParams lists every parameter of the update with its old and new
// value, in the ledger's order. raw is a protocol-parameters document in the
// shape of `cardano-cli query protocol-parameters` (the hosted light-mode file)
// or of a Koios epoch_params row; nil means there is no source. Nothing is left
// out: a parameter whose current value the document does not give is listed
// with the reason.
func DescribeParams(changes []ParamChange, raw json.RawMessage) []ParamDiff {
	var doc any
	why := "no parameter document is available"
	if len(raw) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			doc, why = nil, "the parameter document does not parse"
		}
	}
	byName := map[string]ParamChange{}
	for _, c := range changes {
		byName[c.Name] = c
	}
	var out []ParamDiff
	for _, s := range ParamSpecs {
		c, ok := byName[s.Name]
		if !ok {
			continue
		}
		d := ParamDiff{Name: s.Name, New: displayParam(s, c.Value), Why: why}
		if doc != nil {
			cur := func() (any, bool) {
				for _, path := range [][]string{s.Doc, s.EpochDoc} {
					if v, ok := pathValue(doc, path); ok {
						return v, true
					}
				}
				return nil, false
			}
			if s.Type == ParamCostModels {
				// Whole arrays are replaced: say how many values of each differ.
				if cm, err := ParseCostModels([]byte(c.Value)); err == nil {
					v, _ := cur()
					d.New = costModelChange(cm, v)
					if d.Old = costModelCurrent(cm, v); d.Old == "" {
						d.Why = "the parameter document has no " + s.Name
					} else {
						d.Why = ""
					}
				}
				out = append(out, d)
				continue
			}
			d.Why = "the parameter document has no " + s.Name
			for _, path := range [][]string{s.Doc, s.EpochDoc} {
				if v, ok := pathValue(doc, path); ok {
					if txt, ok := displayDocValue(s, v); ok {
						d.Old, d.Why = txt, ""
						break
					}
				}
			}
		}
		out = append(out, d)
	}
	return out
}

func pathValue(doc any, path []string) (any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	cur := doc
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[k]; !ok {
			return nil, false
		}
	}
	return cur, cur != nil
}

func displayParam(s ParamSpec, v string) string {
	switch s.Type {
	case ParamRational:
		if r, err := (ParamChange{Name: s.Name, Value: v}).Rational(); err == nil {
			return FormatRational(r)
		}
	case ParamCostModels:
		if cm, err := ParseCostModels([]byte(v)); err == nil {
			return cm.Summary()
		}
	}
	return v
}

// Summary says which languages a cost-model update sets and how many values.
func (c CostModels) Summary() string {
	var parts []string
	for i, name := range languageNames {
		if arr, ok := c[uint8(i)]; ok {
			parts = append(parts, fmt.Sprintf("%s (%d values)", name, len(arr)))
		}
	}
	return strings.Join(parts, ", ")
}

func displayDocValue(s ParamSpec, v any) (string, bool) {
	switch s.Type {
	case ParamRational:
		var txt string
		switch x := v.(type) {
		case json.Number:
			txt = x.String()
		case string:
			txt = x
		default:
			return "", false
		}
		r, ok := new(big.Rat).SetString(txt)
		if !ok || !r.Num().IsUint64() || !r.Denom().IsUint64() {
			return "", false
		}
		return FormatRational(chain.Rational{Num: r.Num().Uint64(), Den: r.Denom().Uint64()}), true
	case ParamUnits:
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		mem, ok1 := numberOf(m["memory"])
		steps, ok2 := numberOf(m["steps"])
		if !ok1 || !ok2 {
			return "", false
		}
		return Units{Memory: mem, Steps: steps}.Text(), true
	case ParamCostModels:
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		var parts []string
		for _, name := range languageNames {
			if arr, ok := m[name].([]any); ok {
				parts = append(parts, fmt.Sprintf("%s (%d values)", name, len(arr)))
			}
		}
		if len(parts) == 0 {
			return "", false
		}
		return strings.Join(parts, ", "), true
	}
	n, ok := numberOf(v)
	if !ok {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}

func numberOf(v any) (uint64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseUint(x.String(), 10, 64)
		return n, err == nil
	case string:
		return parseDigits(x)
	}
	return 0, false
}

// ErrCostModelLength: a cost model whose length is not the current one's.
var ErrCostModelLength = fmt.Errorf("%w: cost model length", ErrParam)

// ErrCostModelUnchecked: the update names a language whose current model cannot
// be read as an array of values (a provider that serves the models keyed by
// name, an absent document), so the length cannot be compared. The check fails
// closed: it refuses unless the length change is allowed.
var ErrCostModelUnchecked = fmt.Errorf("%w: the current cost model cannot be read", ErrCostModelLength)

// currentCostModels reads the current cost models of a protocol parameters
// document, either shape, as name to array; a language whose model is not an
// array is absent from the result.
func currentCostModels(raw json.RawMessage) map[string][]any {
	out := map[string][]any{}
	if len(raw) == 0 {
		return out
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var doc any
	if dec.Decode(&doc) != nil {
		return out
	}
	cur, ok := pathValue(doc, []string{"costModels"})
	if !ok {
		cur, _ = pathValue(doc, []string{"cost_models"})
	}
	m, _ := cur.(map[string]any)
	for name, v := range m {
		if arr, ok := v.([]any); ok {
			out[name] = arr
		}
	}
	return out
}

// namedCostModels lists, per cost-model change, the languages it names with the
// number of values given.
func namedCostModels(changes []ParamChange) (map[string]int, bool) {
	named, any := map[string]int{}, false
	for _, c := range changes {
		if c.Name != "cost-models" {
			continue
		}
		cm, err := ParseCostModels([]byte(c.Value))
		if err != nil {
			continue
		}
		for i, name := range languageNames {
			if arr, ok := cm[uint8(i)]; ok {
				named[name], any = len(arr), true
			}
		}
	}
	return named, any
}

// CostModelUnchecked lists the languages a cost model update names whose
// current model cannot be read as an array in raw, so that the length was not
// checked: a summary of an update that was allowed to go on says so.
func CostModelUnchecked(changes []ParamChange, raw json.RawMessage) []string {
	named, _ := namedCostModels(changes)
	cur := currentCostModels(raw)
	var out []string
	for _, name := range languageNames {
		if _, ok := named[name]; !ok {
			continue
		}
		if _, ok := cur[name]; !ok {
			out = append(out, name)
		}
	}
	return out
}

// CheckCostModelLengths refuses a cost model update whose array has another
// number of values than the current model of that language in raw (a protocol
// parameters document, either shape). A length change is how a new Plutus
// version's model arrives, so it is allowed only when asked for. It fails
// closed: when the current model of a language the update names cannot be read
// as an array (a document with the models keyed by name, no document), the
// length cannot be compared and the update is refused with ErrCostModelUnchecked
// unless the length change is allowed, in which case the caller lists
// CostModelUnchecked in the summary.
func CheckCostModelLengths(changes []ParamChange, raw json.RawMessage) error {
	named, any := namedCostModels(changes)
	if !any {
		return nil
	}
	cur := currentCostModels(raw)
	for _, name := range languageNames {
		n, ok := named[name]
		if !ok {
			continue
		}
		old, ok := cur[name]
		if !ok {
			return fmt.Errorf("%w: the %s model of the protocol parameters is not an array of values (or the parameters hold none), so the length of the new model, %d values, cannot be checked: pass --allow-cost-model-length-change to go on without the check", ErrCostModelUnchecked, name, n)
		}
		if len(old) != n {
			return fmt.Errorf("%w: the new %s model has %d values, the current one has %d: pass --allow-cost-model-length-change if the length is meant to change", ErrCostModelLength, name, n, len(old))
		}
	}
	return nil
}

// maxDiffIndices bounds the differing values a summary lists per language.
const maxDiffIndices = 12

// costModelChange describes the new arrays against the current ones: the length
// and how many positions differ (all of them when there is no current array).
func costModelChange(cm CostModels, cur any) string {
	m, _ := cur.(map[string]any)
	var parts []string
	for i, name := range languageNames {
		arr, ok := cm[uint8(i)]
		if !ok {
			continue
		}
		old, _ := m[name].([]any)
		if old == nil {
			parts = append(parts, fmt.Sprintf("%s (%d values, current unknown)", name, len(arr)))
			continue
		}
		var diffs []string
		n := 0
		at := func(j int, oldText, newText string) {
			n++
			if len(diffs) < maxDiffIndices {
				diffs = append(diffs, fmt.Sprintf("[%d] %s -> %s", j, oldText, newText))
			}
		}
		for j := 0; j < len(arr) || j < len(old); j++ {
			switch {
			case j >= len(old):
				at(j, "(none)", strconv.FormatInt(arr[j], 10))
			case j >= len(arr):
				ot := "?"
				if num, ok := old[j].(json.Number); ok {
					ot = num.String()
				}
				at(j, ot, "(none)")
			default:
				if num, ok := old[j].(json.Number); !ok || num.String() != strconv.FormatInt(arr[j], 10) {
					ot := "?"
					if ok {
						ot = num.String()
					}
					at(j, ot, strconv.FormatInt(arr[j], 10))
				}
			}
		}
		head := fmt.Sprintf("%s (%d values, current %d; %d differ", name, len(arr), len(old), n)
		if n == 0 {
			parts = append(parts, head+")")
			continue
		}
		list := strings.Join(diffs, ", ")
		if n > len(diffs) {
			list += fmt.Sprintf(", and %d more", n-len(diffs))
		}
		parts = append(parts, head+": "+list+")")
	}
	return strings.Join(parts, ", ")
}

// costModelCurrent describes the current arrays of the languages the update
// sets, empty when the document has none of them.
func costModelCurrent(cm CostModels, cur any) string {
	m, _ := cur.(map[string]any)
	var parts []string
	for i, name := range languageNames {
		if _, ok := cm[uint8(i)]; !ok {
			continue
		}
		if old, ok := m[name].([]any); ok {
			parts = append(parts, fmt.Sprintf("%s (%d values)", name, len(old)))
		}
	}
	return strings.Join(parts, ", ")
}
