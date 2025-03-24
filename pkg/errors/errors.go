package errors

import (
	"errors"
)

var (
	ErrNilHashFactory  = errors.New("nil hash factory")
	ErrBadPrefixLength = errors.New("bad prefix length")
	ErrTooLargePrefix  = errors.New("too large prefix")
)
