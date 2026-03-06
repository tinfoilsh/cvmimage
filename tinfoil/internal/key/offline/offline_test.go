package offline

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOfflineKeySignValidate(t *testing.T) {
	signer, err := NewSigner(24 * time.Hour)
	assert.Nil(t, err)

	key1, err := signer.NewAPIKey()
	assert.Nil(t, err)

	key2, err := signer.NewAPIKey()
	assert.Nil(t, err)

	assert.NotEqual(t, key1, key2)

	verifier, err := NewValidator(signer.PubKey())

	assert.Nil(t, verifier.Validate(key1))
	assert.Nil(t, verifier.Validate(key2))
	assert.NotNil(t, verifier.Validate(key1+"a"))
}

func TestOfflineKeyExpiry(t *testing.T) {
	signer, err := NewSigner(1 * time.Second)
	assert.Nil(t, err)

	key, err := signer.NewAPIKey()
	assert.Nil(t, err)

	verifier, err := NewValidator(signer.PubKey())
	assert.Nil(t, err)

	assert.Nil(t, verifier.Validate(key))
	time.Sleep(2 * time.Second)
	assert.NotNil(t, verifier.Validate(key))
}
