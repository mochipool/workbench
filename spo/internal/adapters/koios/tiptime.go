package koios

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// TipTime implements ports.TipTimeReader: the block_time (unix seconds) of
// /tip, as recorded in testdata/tip.json. An answer without it is an error,
// never a guess.
func (c *Client) TipTime(ctx context.Context) (time.Time, error) {
	body, err := c.get(ctx, "tip", "/tip", "", true)
	if err != nil {
		return time.Time{}, err
	}
	var rows []struct {
		Time *uintVal `json:"block_time"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return time.Time{}, fmt.Errorf("koios tip: not a JSON array: %w", err)
	}
	if len(rows) == 0 || rows[0].Time == nil {
		return time.Time{}, errors.New("koios tip: answer has no block_time")
	}
	return time.Unix(int64(*rows[0].Time), 0), nil
}
