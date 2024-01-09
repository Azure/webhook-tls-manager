package keypool

import (
	"crypto/rand"
	"crypto/rsa"
)

func GenerateKey(length int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, length)
}
