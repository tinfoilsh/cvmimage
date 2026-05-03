package key

import (
	"tinfoil/internal/key/offline"
	"tinfoil/internal/key/online"
)

type Validator interface {
	Validate(apiKey string) error
	ValidateWithIP(apiKey string) error
}

var (
	_ Validator = &offline.Validator{}
	_ Validator = &online.Validator{}
)
