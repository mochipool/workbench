package koios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// LightParameters reads the hosted "light-mode parameters" file that upstream
// fetches from lightModeParametersURL (SPO-Clight-EXT-001, SPO-Cconf-EXT-001).
//
// It is a second constructor behind the same ports.ProtocolParametersReader,
// not part of Client, because it is a different provider: a third-party file
// host with no Koios token (SPO-Clight-INV-004), a different document shape
// (cardano-cli camelCase JSON plus a "sposcriptsLightMode" metadata object,
// SPO-Clight-OUT-001) and its own trust checks. Raw is that document, which
// is what cardano-cli accepts as a protocol-parameters file.
type LightParameters struct {
	c       *Client
	magic   string
	cli     string
	now     func() time.Time
	rawHost string
}

var _ ports.ProtocolParametersReader = (*LightParameters)(nil)

// LightConfig builds a LightParameters.
type LightConfig struct {
	URL        string // lightModeParametersURL (https unless loopback)
	Magic      string // expected sposcriptsLightMode.magic, e.g. "2" or "mainnet" (SPO-Cconf-PRE-007)
	LocalCLI   string // local cardano-cli version; empty skips SPO-Cconf-PRE-008
	HTTPClient *http.Client
	Timeout    time.Duration
	MaxBody    int64
	Now        func() time.Time
}

// MaxLightAge is how old lastUpdate may be (SPO-Cconf-PRE-006: 6 hours).
const MaxLightAge = 6 * time.Hour

// NewLightParameters validates the configuration.
func NewLightParameters(cfg LightConfig) (*LightParameters, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" {
		return nil, errors.New("koios light parameters: URL is not a valid absolute URL")
	}
	if u.User != nil {
		return nil, errors.New("koios light parameters: URL must not carry credentials")
	}
	if err := checkScheme(u); err != nil {
		return nil, fmt.Errorf("koios light parameters: %w", err)
	}
	if cfg.Magic == "" {
		return nil, errors.New("koios light parameters: expected network magic is required")
	}
	c := &Client{base: u, source: chain.Source("light-parameters " + u.Host),
		timeout: cfg.Timeout, long: defaultLongTimeout, maxBody: cfg.MaxBody, hc: newHTTPClient(cfg.HTTPClient)}
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	if c.maxBody <= 0 {
		c.maxBody = defaultMaxBody
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &LightParameters{c: c, magic: cfg.Magic, cli: cfg.LocalCLI, now: now}, nil
}

// Source implements ports.ChainSource.
func (l *LightParameters) Source() chain.Source { return l.c.source }

type lightDoc struct {
	TxFeePerByte        *uintVal     `json:"txFeePerByte"`
	TxFeeFixed          *uintVal     `json:"txFeeFixed"`
	UtxoCostPerByte     *uintVal     `json:"utxoCostPerByte"`
	StakeAddressDeposit *uintVal     `json:"stakeAddressDeposit"`
	StakePoolDeposit    *uintVal     `json:"stakePoolDeposit"`
	DRepDeposit         *uintVal     `json:"dRepDeposit"`
	GovActionDeposit    *uintVal     `json:"govActionDeposit"`
	MaxTxSize           *uintVal     `json:"maxTxSize"`
	MaxValueSize        *uintVal     `json:"maxValueSize"`
	RefScript           *rationalVal `json:"minFeeRefScriptCostPerByte"`
	ProtocolVersion     *struct {
		Major *uintVal `json:"major"`
		Minor *uintVal `json:"minor"`
	} `json:"protocolVersion"`
	Meta *struct {
		LastUpdate string          `json:"lastUpdate"`
		Magic      json.RawMessage `json:"magic"`
		VersionCLI string          `json:"versionCLI"`
		LastTip    struct {
			Epoch *uintVal `json:"epoch"`
		} `json:"lastTip"`
	} `json:"sposcriptsLightMode"`
}

// ProtocolParameters fetches the file and applies the refusals upstream
// makes in its prologue: the fetch must succeed with status 200
// (SPO-Clight-PRE-001, SPO-Cconf-PRE-005), the body must be JSON
// (SPO-Clight-INV-005), lastUpdate must not be older than six hours
// (SPO-Cconf-PRE-006; one-sided as upstream, a future lastUpdate passes),
// the magic must equal the expected one (SPO-Cconf-PRE-007), and, when a
// local cardano-cli version is configured, it must not be older than
// versionCLI (SPO-Cconf-PRE-008). Upstream's unspecified behaviour for a
// missing or unparsable lastUpdate (Cconf open question) is a refusal here.
func (l *LightParameters) fetch(ctx context.Context) ([]byte, lightDoc, error) {
	// SPO-Clight-EXT-001: cache-buster rnd=<unix seconds>, no-cache header,
	// no Koios authorization (auth false). Compression is negotiated by the
	// Go transport.
	q := url.Values{"rnd": {strconv.FormatInt(l.now().Unix(), 10)}}.Encode()
	if l.c.base.RawQuery != "" {
		q = l.c.base.RawQuery + "&" + q
	}
	status, body, err := l.c.do(ctx, request{op: "light parameters", method: "GET", query: q, retry: true, noCache: true})
	if err != nil {
		return nil, lightDoc{}, err
	}
	if status != 200 {
		return nil, lightDoc{}, fmt.Errorf("koios light parameters: %s%s answered HTTP %d",
			l.c.base.Host, l.c.base.Path, status)
	}
	var d lightDoc
	if err := strictUnmarshal(body, &d); err != nil {
		return nil, lightDoc{}, fmt.Errorf("koios light parameters: not a JSON parameters document: %w", err)
	}
	if d.Meta == nil {
		return nil, lightDoc{}, errors.New("koios light parameters: no sposcriptsLightMode object")
	}
	if err := l.check(d.Meta.LastUpdate, d.Meta.Magic, d.Meta.VersionCLI); err != nil {
		return nil, lightDoc{}, err
	}
	return body, d, nil
}

func (l *LightParameters) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	body, d, err := l.fetch(ctx)
	if err != nil {
		return chain.ProtocolParameters{}, err
	}
	var miss []string
	need := func(name string, v *uintVal) uint64 {
		if v == nil {
			miss = append(miss, name)
			return 0
		}
		return uint64(*v)
	}
	out := chain.ProtocolParameters{
		TxFeePerByte:        chain.Lovelace(need("txFeePerByte", d.TxFeePerByte)),
		TxFeeFixed:          chain.Lovelace(need("txFeeFixed", d.TxFeeFixed)),
		CoinsPerUTxOByte:    chain.Lovelace(need("utxoCostPerByte", d.UtxoCostPerByte)),
		StakeAddressDeposit: chain.Lovelace(need("stakeAddressDeposit", d.StakeAddressDeposit)),
		StakePoolDeposit:    chain.Lovelace(need("stakePoolDeposit", d.StakePoolDeposit)),
		DRepDeposit:         chain.Lovelace(need("dRepDeposit", d.DRepDeposit)),
		GovActionDeposit:    chain.Lovelace(need("govActionDeposit", d.GovActionDeposit)),
		MaxTxSize:           need("maxTxSize", d.MaxTxSize),
		MaxValueSize:        need("maxValueSize", d.MaxValueSize),
		Raw:                 append(json.RawMessage(nil), body...),
	}
	if d.ProtocolVersion == nil {
		miss = append(miss, "protocolVersion")
	} else {
		out.ProtocolMajor = need("protocolVersion.major", d.ProtocolVersion.Major)
		out.ProtocolMinor = need("protocolVersion.minor", d.ProtocolVersion.Minor)
	}
	if d.RefScript == nil {
		miss = append(miss, "minFeeRefScriptCostPerByte")
	} else {
		out.MinFeeRefScriptCostPerByte = chain.Rational(*d.RefScript)
	}
	if d.Meta.LastTip.Epoch != nil {
		out.Epoch = uint64(*d.Meta.LastTip.Epoch)
	}
	if len(miss) > 0 {
		return chain.ProtocolParameters{}, fmt.Errorf("koios light parameters: missing %s", strings.Join(miss, ", "))
	}
	return out, nil
}

func (l *LightParameters) check(lastUpdate string, magicRaw json.RawMessage, versionCLI string) error {
	var last time.Time
	var perr error
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC3339} {
		if last, perr = time.Parse(layout, lastUpdate); perr == nil {
			break
		}
	}
	if perr != nil {
		return fmt.Errorf("koios light parameters: lastUpdate %q is not a date", prefix([]byte(lastUpdate)))
	}
	if age := l.now().Sub(last); age > MaxLightAge { // SPO-Cconf-PRE-006
		return fmt.Errorf("koios light parameters: last updated %s ago, older than %s", age.Round(time.Minute), MaxLightAge)
	}
	var magic string
	if len(magicRaw) > 0 && magicRaw[0] == '"' {
		if err := json.Unmarshal(magicRaw, &magic); err != nil {
			return fmt.Errorf("koios light parameters: magic: %w", err)
		}
	} else {
		magic = string(magicRaw)
	}
	if magic != l.magic { // SPO-Cconf-PRE-007
		return fmt.Errorf("koios light parameters: network magic %q, expected %q", prefix([]byte(magic)), l.magic)
	}
	if l.cli != "" { // SPO-Cconf-PRE-008
		cmp, err := compareVersions(l.cli, versionCLI)
		if err != nil {
			return fmt.Errorf("koios light parameters: cardano-cli version: %w", err)
		}
		if cmp < 0 {
			return fmt.Errorf("koios light parameters: need cardano-cli %s or newer, have %s", prefix([]byte(versionCLI)), l.cli)
		}
	}
	return nil
}

// compareVersions compares dotted numeric versions ("10.14.0.0"); missing
// trailing segments count as 0.
func compareVersions(a, b string) (int, error) {
	pa, err := versionParts(a)
	if err != nil {
		return 0, err
	}
	pb, err := versionParts(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y uint64
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func versionParts(v string) ([]uint64, error) {
	var out []uint64
	for _, s := range strings.Split(v, ".") {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a dotted numeric version", prefix([]byte(v)))
		}
		out = append(out, n)
	}
	return out, nil
}
