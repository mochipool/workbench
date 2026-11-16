package assets

// Keys lists the record's keys in order.
func (r Record) Keys() []string { return append([]string(nil), r.keys...) }

// Has reports whether the record has the key.
func (r Record) Has(k string) bool { _, ok := r.vals[k]; return ok }
