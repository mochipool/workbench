//go:build plainlayout

package archtest

// buildTags are the tags the import graph is listed with, so that
// `go test -tags plainlayout ./internal/archtest/` checks the tagged build too.
const buildTags = "plainlayout"
