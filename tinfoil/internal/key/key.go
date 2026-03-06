package key

import (
	"errors"

	"tinfoil/internal/key/offline"
	"tinfoil/internal/key/online"
)

var ErrAPIKeyRequired = errors.New("API key required")

type Validator interface {
	Validate(apiKey string) error
}

var (
	_ Validator = &offline.Validator{}
	_ Validator = &online.Validator{}
)
