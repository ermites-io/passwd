package passwd

// very good point and advice
// https://dave.cheney.net/2016/04/07/constant-errors
// also avoid your error checks can be diverted cross packages
// when in usage in the rest of an package ecosystem

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrParse       = Error("parse error")
	ErrUnsupported = Error("unsupported")
	ErrMismatch    = Error("mismatch")
	ErrUnsafe      = Error("unsafe parameters")
)
