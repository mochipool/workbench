package parity

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/koios"
	"github.com/mochipool/workbench/spo/internal/app/poll"
)

// A hand-written CIP-94 poll (no real poll transaction is recorded; the
// metadata is in the shape Koios answers for label 94): one question line and
// three options, the last of two lines. It is the question of a transaction
// that does not exist; the stand-in Koios answers it.
const pollTx = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

const pollMetadata = `[{"tx_hash":"` + pollTx + `","metadata":{"94":{"0":["Should the network do X? é"],"1":[["Yes"],["No"],["Abstain, ","for now"]]}}}]`

// The answer metadata of upstream's 13a (the testnet script, run through the
// workbench in light mode against a stand-in Koios that answers the poll) is
// byte-equal to the port's for the same question and choice: the file name
// carries the question hash, the content is {94: {2: hash, 3: index}}.
// Upstream's prompts (index, "Is this correct?") are answered on a terminal.
//
// spec: SPO-13a-EXT-001, SPO-13a-INV-001, SPO-13a-INV-002, SPO-13a-OUT-001, SPO-13a-OUT-002, SPO-13a-PR-001, SPO-13a-OUT-003
func TestPollAnswerMatchesUpstream(t *testing.T) {
	e := setup(t)
	k := newReplay(t, loadExchanges(t, filepath.Join(airgapFx, "exchanges.json")), time.Now().UTC().Format(time.RFC1123Z))
	var asked string
	k.custom = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		if r.Method == "POST" && r.URL.Path == "/api/v1/tx_metadata" {
			asked = string(body)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, pollMetadata)
			return true
		}
		return false
	}
	up := e.lightWorkspace(t, k)
	if code := e.upstreamAnswers(t, up, "1\ny\n", "13a_spoPoll.sh", pollTx); code != 0 {
		t.Skipf("upstream 13a exited %d (the testnet script cannot run here)", code)
	}
	if !strings.Contains(strings.ReplaceAll(asked, " ", ""), `"_tx_hashes":["`+pollTx+`"]`) {
		t.Errorf("upstream asked Koios %q", asked)
	}
	files, _ := filepath.Glob(filepath.Join(up, "spopoll_*.cbor"))
	if len(files) != 1 {
		t.Fatalf("upstream wrote %v", files)
	}
	theirs, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}

	client, err := koios.New(koios.Config{BaseURL: k.KoiosAPI(), Network: "preview"})
	if err != nil {
		t.Fatal(err)
	}
	show := poll.ShowPoll{Questions: client}
	ans, view, err := poll.BuildPollAnswer{Show: show}.Run(context.Background(), strings.ToUpper(pollTx), 1)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(files[0]) != ans.FileName {
		t.Errorf("file name: upstream %s, port %s", filepath.Base(files[0]), ans.FileName)
	}
	if string(theirs) != string(ans.CBOR) {
		t.Errorf("answer CBOR: upstream %s, port %s", hex.EncodeToString(theirs), hex.EncodeToString(ans.CBOR))
	}
	if view.Text != "Should the network do X? é" || len(view.Options) != 3 || view.Options[2] != "Abstain, for now" {
		t.Errorf("view %+v", view)
	}
}
