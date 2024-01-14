package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	pubKey := privKey.Public()
	assert.Equal(t, pubKeyLen, len(pubKey.Bytes()))
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	msg := []byte("hello")
	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(privKey.Public(), msg))
	// invalid msg
	assert.False(t, sig.Verify(privKey.Public(), []byte("world")))
	// invalid public key
	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sig.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed = "a4c2a67bda26bdd1ba9f061715be2854f1e8aee57d16f225d78c55c6ab817fb2"
		privKey = NewPrivateKeyFromString(seed)
		addressStr = "1c4d1b2cbdeecfc4e1c0a8e5490efa4c9a4a4040"
	)
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
}