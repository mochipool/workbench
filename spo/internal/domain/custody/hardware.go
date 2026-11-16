package custody

import (
	"fmt"
	"regexp"
	"strings"
)

// Vendor is the maker of a hardware wallet, as `cardano-hw-cli device
// version` names it (spec: SPO-Chw-EXT-003).
type Vendor string

const (
	VendorLedger   Vendor = "Ledger"
	VendorTrezor   Vendor = "Trezor"
	VendorKeystone Vendor = "Keystone"
)

// Vendors lists the vendors cardano-hw-cli supports.
func Vendors() []Vendor { return []Vendor{VendorLedger, VendorTrezor, VendorKeystone} }

// ParseVendor reads a vendor name case-insensitively (SPO-Chw-EXT-003).
func ParseVendor(s string) (Vendor, bool) {
	for _, v := range Vendors() {
		if strings.EqualFold(s, string(v)) {
			return v, true
		}
	}
	return "", false
}

// FeatUnrestricted is the unrestricted signing mode of the device
// (`--allow-unrestricted-mode`; Ledger app 8 or newer with expert mode): the
// device signs a transaction that holds a certificate or a vote it does not
// own and shows every element. It is a feature of its own so that it is never
// implied: a use case puts it in the Demand only when the operator allowed it
// (SPO-21b-PR-001, SPO-21b-SEC-003, SPO-24b-PR-001).
const FeatUnrestricted Feature = "unrestricted-signing-mode"

// OpHardwarePolicyID asks the device for the id of a policy script it holds
// the key of (SPO-10-EXT-005): `transaction policyid` makes the device show
// the script's expiry slot.
const OpHardwarePolicyID Operation = "derive-policy-id"

// HardwareGrant is what a row lets a vendor's device do with one role's key.
type HardwareGrant struct {
	Role Role
	Ops  []Operation // operations with no feature limit
	// TxFeatures are the transaction features a witness may contain (the
	// grant also makes OpWitnessTx available for the role).
	TxFeatures []Feature
}

// HardwareRow says that a device of one of Vendors whose app or firmware
// version is at least Min can do Grants. Rows add up: a device gets the union
// of every row that matches it. A firmware release that adds a feature is one
// new row. Min "" means the session's own minimum (SPO-Chw-IN-002), which the
// session has already enforced.
//
// The profile claims only what a row states. Where the specs do not say that
// a device can do something, no row says it, and the plan refuses it (ADR 0008).
type HardwareRow struct {
	Source  string // the requirement ids the row comes from
	Vendors []Vendor
	Min     string
	Grants  []HardwareGrant
}

var (
	allVendors       = []Vendor{VendorLedger, VendorTrezor, VendorKeystone}
	ledgerKeystone   = []Vendor{VendorLedger, VendorKeystone}
	ledgerOnly       = []Vendor{VendorLedger}
	exportOnly       = []Operation{OpExportVKey}
	featsFundedTx    = []Feature{FeatMultiAssetOutput, FeatMetadata, FeatWithdrawal, FeatMint, FeatStakeRegistration, FeatStakeDeregistration, FeatStakeDelegation, FeatVoteDelegation, FeatPoolRegistrationOwner, FeatPoolRegistrationOper, FeatPoolRetirement}
	featsStakeTx     = []Feature{FeatMultiAssetOutput, FeatMetadata, FeatWithdrawal, FeatStakeRegistration, FeatStakeDeregistration, FeatStakeDelegation, FeatVoteDelegation, FeatPoolRegistrationOwner}
	featsGovernance  = []Feature{FeatDRepRegistration, FeatDRepUpdate, FeatDRepRetirement, FeatCommitteeAuthorize, FeatCommitteeResign}
	featsPoolColdTx  = []Feature{FeatPoolRegistrationOper, FeatPoolRegistrationOwner, FeatPoolRetirement}
	featsCommitteeTx = []Feature{FeatCommitteeAuthorize, FeatCommitteeResign}
)

// HardwareTable is the capability table of the hardware signer: vendor x
// minimum version -> roles, operations and transaction features. Every row
// names the requirements it comes from. Edit rows, not code.
var HardwareTable = []HardwareRow{
	{
		// 02 and 03a call the session with no vendor argument and key-gen for the
		// payment path (1852H or 1854H) and the stake path.
		Source:  "SPO-02-EXT-003, SPO-03a-EXT-002, SPO-03a-EXT-004, SPO-Chw-IF-001",
		Vendors: allVendors,
		Grants: []HardwareGrant{
			{Role: RolePayment, Ops: exportOnly},
			{Role: RoleStake, Ops: exportOnly},
		},
	},
	{
		// 10: the policy key at 1855H/1815H/0H and the policy id through the device.
		Source:  "SPO-10-EXT-002, SPO-10-EXT-005, SPO-10-OUT-004",
		Vendors: allVendors,
		Grants:  []HardwareGrant{{Role: RolePolicy, Ops: []Operation{OpExportVKey, OpHardwarePolicyID}, TxFeatures: []Feature{FeatMint, FeatMultiAssetOutput, FeatMetadata}}},
	},
	{
		// The sessions of the key-generation, opcert, committee and DRep scripts are
		// restricted to Ledger or Keystone ("Ledger|Keystone"). 15 signs the Calidus
		// registration with the pool cold key through `message sign` on the same two.
		Source:  "SPO-04a-EXT-003, SPO-04d-EXT-004, SPO-15-EXT-004, SPO-21a-PRE-011, SPO-23a-PRE-008, SPO-23b-PRE-007, SPO-Chw-PRE-003",
		Vendors: ledgerKeystone,
		Grants: []HardwareGrant{
			{Role: RolePoolCold, Ops: []Operation{OpExportVKey, OpIssueOpCert, OpSignMessage}},
			{Role: RoleDRep, Ops: exportOnly},
			{Role: RoleCommitteeCold, Ops: exportOnly},
			{Role: RoleCommitteeHot, Ops: exportOnly},
		},
	},
	{
		// 09a: the Catalyst voting key at 1694H/1815H/0H/0/0 and the CIP-36
		// registration signed by a hardware stake key. The session lowers the Ledger
		// minimum to 6.0.3 for it. The script does not restrict the vendor, but only
		// the Ledger version is mentioned, so only Ledger is claimed.
		Source:  "SPO-09a-EXT-002, SPO-09a-EXT-004, SPO-09a-INV-005",
		Vendors: ledgerOnly,
		Min:     "6.0.3",
		Grants: []HardwareGrant{
			{Role: RoleCatalystVote, Ops: exportOnly},
			{Role: RoleStake, Ops: []Operation{OpSignCip36}},
		},
	},
	{
		// The transaction scripts' hardware paths start the session with no vendor
		// restriction: 01_sendLovelaces and 01_sendAssets (payment, change key), 01_claimRewards,
		// 03b, 05b, 06, 08b, 22b (stake), 11a and 11b (policy and payment), 05c and 05d
		// (owner staking key), 07b.
		Source:  "SPO-Ptx-EXT-005, SPO-01sendLovelaces-EXT-002, SPO-01sendAssets-EXT-003, SPO-03b-EXT-003, SPO-05c-EXT-006, SPO-05d-EXT-001, SPO-07b-EXT-001, SPO-08b-EXT-002, SPO-22b-EXT-001",
		Vendors: allVendors,
		Grants: []HardwareGrant{
			{Role: RolePayment, TxFeatures: featsFundedTx},
			{Role: RoleStake, TxFeatures: featsStakeTx},
		},
	},
	{
		// The pool cold key, the DRep key, the committee cold key, and the payment key that
		// pays together with them: the keys that can only exist on Ledger or Keystone
		// (SPO-04a-EXT-003, SPO-21a-PRE-011, SPO-23a-PRE-008), for 05c, 07b, 21b, 21d, 23c, 23e.
		// 21b registers or updates with the same signing forms (SPO-21b-INV-006 does not
		// branch on the kind, SPO-21b-EXT-006), so the DRep update certificate is granted
		// with the registration; the specs do not name a device app version for it.
		Source:  "SPO-05c-EXT-004, SPO-07b-EXT-001, SPO-21b-INV-006, SPO-21b-EXT-006, SPO-21d-INV-004, SPO-23c-INV-006",
		Vendors: ledgerKeystone,
		Grants: []HardwareGrant{
			{Role: RolePoolCold, TxFeatures: featsPoolColdTx},
			{Role: RoleDRep, TxFeatures: []Feature{FeatDRepRegistration, FeatDRepUpdate, FeatDRepRetirement}},
			{Role: RoleCommitteeCold, TxFeatures: featsCommitteeTx},
			{Role: RolePayment, TxFeatures: featsGovernance},
		},
	},
	{
		// 24b opens a Ledger session (SPO-24b-EXT-001, SPO-24b-EXT-002): a vote is
		// witnessed on Ledger only, with the voter key (DRep, committee hot or pool cold)
		// and the payment key on the same device.
		Source:  "SPO-24b-EXT-001, SPO-24b-EXT-002, SPO-24b-PRE-008",
		Vendors: ledgerOnly,
		Grants: []HardwareGrant{
			{Role: RolePayment, TxFeatures: []Feature{FeatVote}},
			{Role: RoleDRep, TxFeatures: []Feature{FeatVote}},
			{Role: RoleCommitteeHot, TxFeatures: []Feature{FeatVote}},
			{Role: RolePoolCold, TxFeatures: []Feature{FeatVote}},
		},
	},
	{
		// Unrestricted signing mode: the hw-cli help ties it to Ledger app 8 or newer with
		// expert mode. 21b and 21d use it for a hardware payer with a key-file DRep, 24b for
		// several proposals at once. It is a feature a Demand must ask for.
		Source:  "SPO-21b-PR-001, SPO-21b-SEC-003, SPO-21d-INV-004, SPO-24b-PR-001; cardano-hw-cli 1.20.0 `transaction witness --help`",
		Vendors: ledgerOnly,
		Min:     "8.0.0",
		Grants: []HardwareGrant{
			{Role: RolePayment, TxFeatures: []Feature{FeatUnrestricted}},
			{Role: RoleDRep, TxFeatures: []Feature{FeatUnrestricted}},
			{Role: RoleCommitteeHot, TxFeatures: []Feature{FeatUnrestricted}},
			{Role: RolePoolCold, TxFeatures: []Feature{FeatUnrestricted}},
		},
	},
}

// HardwareProfile builds the profile of a device of the vendor with the given
// app or firmware version from HardwareTable. atLeast orders versions
// (internal/platform/version.AtLeast); the domain does not import it.
func HardwareProfile(v Vendor, version string, atLeast func(have, min string) bool) Profile {
	return profileFromRows(HardwareTable, v, version, atLeast)
}

func profileFromRows(rows []HardwareRow, v Vendor, version string, atLeast func(have, min string) bool) Profile {
	p := NewProfile(fmt.Sprintf("%s app %s", v, version))
	feats := map[Role]map[Feature]struct{}{}
	for _, row := range rows {
		match := false
		for _, rv := range row.Vendors {
			match = match || rv == v
		}
		if !match || (row.Min != "" && !atLeast(version, row.Min)) {
			continue
		}
		for _, g := range row.Grants {
			if len(g.Ops) > 0 {
				p = p.Allow(g.Role, g.Ops...)
			}
			if g.TxFeatures != nil {
				if feats[g.Role] == nil {
					feats[g.Role] = map[Feature]struct{}{}
				}
				for _, f := range g.TxFeatures {
					feats[g.Role][f] = struct{}{}
				}
			}
		}
	}
	for role, set := range feats {
		list := make([]Feature, 0, len(set))
		for f := range set {
			list = append(list, f)
		}
		p = p.AllowTx(role, list...)
	}
	return p
}

// HardwarePath returns the derivation path the specs use for a hardware key of
// the role. account is the wallet account and index the address or key index.
// multisig selects the 1854H purpose of `hwmulti` for a payment key.
//
//	payment  <1852H|1854H>/1815H/<acc>H/0/<idx>   SPO-02-EXT-003, SPO-03a-INV-001
//	stake    1852H/1815H/<acc>H/2/0               SPO-03a-INV-001 (the index is not used)
//	pool     1853H/1815H/0H/<idx>H                SPO-04a-INV-002 (the account is not used)
//	drep     1852H/1815H/<acc>H/3/<idx>           SPO-21a-INV-002
//	cc-cold  1852H/1815H/<acc>H/4/<idx>           SPO-23a-INV-002
//	cc-hot   1852H/1815H/<acc>H/5/<idx>           SPO-23b-INV-002
//	policy   1855H/1815H/0H                       SPO-10-EXT-002
//	voting   1694H/1815H/<acc>H/0/<idx>           SPO-09a-EXT-002 (the script uses 0/0)
//
// A Calidus key has no hardware path: SPO-15-PRE-002 suspends it.
func HardwarePath(role Role, account, index uint32, multisig bool) (string, error) {
	const max = 2147483647
	if account > max || index > max {
		return "", fmt.Errorf("custody: account and index are at most %d", max)
	}
	switch role {
	case RolePayment:
		purpose := "1852H"
		if multisig {
			purpose = "1854H"
		}
		return fmt.Sprintf("%s/1815H/%dH/0/%d", purpose, account, index), nil
	case RoleStake:
		return fmt.Sprintf("1852H/1815H/%dH/2/0", account), nil
	case RolePoolCold:
		return fmt.Sprintf("1853H/1815H/0H/%dH", index), nil
	case RoleDRep:
		return fmt.Sprintf("1852H/1815H/%dH/3/%d", account, index), nil
	case RoleCommitteeCold:
		return fmt.Sprintf("1852H/1815H/%dH/4/%d", account, index), nil
	case RoleCommitteeHot:
		return fmt.Sprintf("1852H/1815H/%dH/5/%d", account, index), nil
	case RolePolicy:
		return "1855H/1815H/0H", nil
	case RoleCatalystVote:
		return fmt.Sprintf("1694H/1815H/%dH/0/%d", account, index), nil
	}
	return "", fmt.Errorf("custody: no hardware derivation path is specified for a %s key", role)
}

var hardwarePathRE = regexp.MustCompile(`^[0-9]{1,10}H?(/[0-9]{1,10}H?)*$`)

// ValidHardwarePath reports whether a path is made of numbers, each at most
// 2147483647, with an optional H for hardened.
func ValidHardwarePath(p string) bool {
	if !hardwarePathRE.MatchString(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		var n uint64
		for _, c := range strings.TrimSuffix(part, "H") {
			n = n*10 + uint64(c-'0')
		}
		if n > 2147483647 {
			return false
		}
	}
	return true
}

// PlanGenerationWith is PlanGeneration with a signer for hardware keys: a key
// held in the vault is met by the software generators, any other holder by the
// profile profileOf returns for it (the hardware signer's). A use case calls it
// instead of PlanGeneration when a hardware signer is configured.
func PlanGenerationWith(profileOf func(KeyRef) (Profile, error), keys ...KeyRef) (Plan, error) {
	slots := make([]Slot, len(keys))
	for i, k := range keys {
		slots[i] = Slot{Label: "generate " + string(k.Role) + " key", Key: k,
			Demand: Demand{Role: k.Role, Operation: OpExportVKey}}
	}
	soft := SoftwareGenerator()
	return NewPlan(slots, func(k KeyRef) (Profile, error) {
		if k.Holder == HolderVault || k.Holder == "" {
			return soft, nil
		}
		if k.Holder == HolderHardware && profileOf != nil {
			return profileOf(k)
		}
		return Profile{}, fmt.Errorf("no signer is configured that can generate keys held by %s", k.Holder)
	})
}
