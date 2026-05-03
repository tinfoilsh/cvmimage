package key

import (
	"tinfoil/internal/key/keyreq"
	"tinfoil/internal/key/offline"
	"tinfoil/internal/key/online"
)

// Request is re-exported here so callers can use key.Request without depending
// on the internal keyreq subpackage directly.
type Request = keyreq.Request

type Validator interface {
	Validate(req Request) error
	ValidateWithIP(req Request) error
}

var (
	_ Validator = &offline.Validator{}
	_ Validator = &online.Validator{}
)
