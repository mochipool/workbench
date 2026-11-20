package relayregistry

// SetLoadedVersions claims that n tombstone versions were loaded, so that a test
// of the ceiling does not load a million of them.
func SetLoadedVersions(c *Core, n int) { c.versions = n }
