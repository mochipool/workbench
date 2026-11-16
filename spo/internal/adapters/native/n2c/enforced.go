package n2c

// OpCertCounterEnforced says that the number OpCertCounter returns is the
// counter the node enforces (its consensus state), not the counter of the pool's
// last block (ports.OpCertCounterEnforcer). The two-provider cross-check reads
// it: an indexer's last-block counter may lag this one by a certificate.
func (c *Client) OpCertCounterEnforced() bool { return true }
