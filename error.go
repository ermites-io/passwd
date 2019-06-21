package passwd

// very good point and advice
// https://dave.cheney.net/2016/04/07/constant-errors
// also avoid your error checks can be diverted cross packages
// when in usage in the rest of an package ecosystem

// Error is the type helping defining errors as constants.
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrParse when a parse error happened
	ErrParse = Error("parse error")
	// ErrUnsupported when a feature is not supported
	ErrUnsupported = Error("unsupported")
	// ErrMismatch is returned when Compare() call does not match
	ErrMismatch = Error("mismatch")
	// ErrValidate is to validate password hashing parameters strength
	ErrUnsafe = Error("unsafe parameters")
)
