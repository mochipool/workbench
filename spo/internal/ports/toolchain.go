// Package ports holds the boundary interfaces of spec/domain/ports.md.
// Use cases depend on these and on nothing outside the domain.
package ports

import "context"

// ToolName names an external tool of the release set.
type ToolName string

const (
	CardanoCLI    ToolName = "cardano-cli"
	CardanoNode   ToolName = "cardano-node"
	CardanoHWCLI  ToolName = "cardano-hw-cli"
	CardanoSigner ToolName = "cardano-signer"
	Bech32        ToolName = "bech32"
	GPG           ToolName = "gpg"
)

// Tool is a located and version-checked external tool.
type Tool struct {
	Name    ToolName
	Path    string // absolute
	Version string // as the tool reports it; empty for tools with no gate
}

// Toolchain locates the external tools and applies the compatibility gates
// before a tool is first used.
type Toolchain interface {
	// Tool returns the tool after checking that it is present and that the
	// version it reports passes the release set's gates. It fails otherwise.
	Tool(ctx context.Context, name ToolName) (Tool, error)
}
