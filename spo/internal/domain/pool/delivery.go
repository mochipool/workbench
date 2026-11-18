package pool

import (
	"bytes"
	"encoding/json"
	"errors"
)

// A delivery file is the sealed payload of `node export`: a fixed magic line, a
// header line and the envelope. The header binds the file to its pool, its kind,
// its KES number and its certificate counter, so the helper can refuse a set
// whose files do not belong together. age gives no sender authentication: the
// header is not a signature, and whoever can write the delivery directory can
// still choose which complete set the node runs.
const deliveryMagic = "SPO-NODE-DELIVERY-1\n"

// DeliveryHeader is the canonical header (struct field order, compact JSON).
type DeliveryHeader struct {
	Format     int    `json:"format"`
	PoolID     string `json:"pool_id"`
	Kind       string `json:"kind"`
	KesNumber  int    `json:"kes_number"`
	Counter    uint64 `json:"opcert_counter"`
	ExportedAt int64  `json:"exported_at"`
}

// ErrDelivery is the refusal of a delivery file with no or a bad header.
var ErrDelivery = errors.New("not a delivery file of this format (magic or header)")

// FrameDelivery returns magic, header line and envelope.
func FrameDelivery(h DeliveryHeader, envelope []byte) ([]byte, error) {
	h.Format = 1
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	out := append([]byte(deliveryMagic), hb...)
	out = append(out, '\n')
	return append(out, envelope...), nil
}

// UnframeDelivery parses a delivery file strictly.
func UnframeDelivery(b []byte) (DeliveryHeader, []byte, error) {
	var h DeliveryHeader
	if !bytes.HasPrefix(b, []byte(deliveryMagic)) {
		return h, nil, ErrDelivery
	}
	rest := b[len(deliveryMagic):]
	i := bytes.IndexByte(rest, '\n')
	if i < 0 || i > 512 {
		return h, nil, ErrDelivery
	}
	dec := json.NewDecoder(bytes.NewReader(rest[:i]))
	dec.DisallowUnknownFields()
	if dec.Decode(&h) != nil || dec.More() || h.Format != 1 || h.PoolID == "" {
		return h, nil, ErrDelivery
	}
	return h, rest[i+1:], nil
}
