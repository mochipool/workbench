package koios

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.PollQuestionReader = (*Client)(nil)

// PollQuestion implements ports.PollQuestionReader: POST /tx_metadata with
// {"_tx_hashes":["<hash>"]} (SPO-13a-EXT-001). The answer must be an array of
// exactly one entry (SPO-13a-PRE-002) with metadata under label 94
// (SPO-13a-PRE-003); `0` is the array of question lines and `1` the array of
// option line arrays. Anything else in the label is refused, not skipped: a
// question that cannot be read in full would commit an answer to a hash of
// something else.
func (c *Client) PollQuestion(ctx context.Context, tx chain.TxID) (ports.PollQuestion, error) {
	body, err := c.postJSON(ctx, "tx_metadata", "/tx_metadata", "", map[string]any{"_tx_hashes": []string{tx.String()}}, false)
	if err != nil {
		return ports.PollQuestion{}, err
	}
	var rows []struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return ports.PollQuestion{}, fmt.Errorf("koios tx_metadata: not a JSON array: %w", err)
	}
	if len(rows) != 1 {
		return ports.PollQuestion{}, fmt.Errorf("%w: koios answered %d", ports.ErrPollNotUnique, len(rows))
	}
	raw, ok := rows[0].Metadata["94"]
	if !ok || string(raw) == "null" {
		return ports.PollQuestion{}, ports.ErrPollNoLabel
	}
	var label struct {
		Lines   []string   `json:"0"`
		Options [][]string `json:"1"`
	}
	if err := json.Unmarshal(raw, &label); err != nil {
		return ports.PollQuestion{}, fmt.Errorf("koios tx_metadata: label 94 is not a poll question (0: text lines, 1: option text lines): %w", err)
	}
	return ports.PollQuestion{Lines: label.Lines, Options: label.Options}, nil
}
