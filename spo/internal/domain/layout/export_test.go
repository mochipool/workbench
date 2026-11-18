package layout

// WrappedKeyForm is the wrapped-key field of a record body, exposed to tests so
// that they can damage it.
type WrappedKeyForm = wrappedKeyForm

// EncodeBodyWithWrappedKeyForm encodes r and lets mutate change the field
// before the CBOR is built (a test of the decoder's refusals).
func EncodeBodyWithWrappedKeyForm(r Record, mutate func(*WrappedKeyForm)) ([]byte, error) {
	return encodeBodyForm(r, mutate)
}
