package keypool

//go:generate mockgen -destination=./mock_keypool/interface.go -package=mock_keypool github.com/Azure/webhook-tls-manager/toolkit/keypool Interface
//go:generate mockgen -destination=./mock_key_generator/key_generator.go -package=mock_key_generator github.com/Azure/webhook-tls-manager/toolkit/keypool KeyGenerator
import (
	"context"
	"crypto/rsa"

	"github.com/sirupsen/logrus"
)

type Interface interface {
	GetKey(context.Context, logrus.Entry) (*rsa.PrivateKey, error)
	CurrentSize() int

	// GenerateKey(length int) (*rsa.PrivateKey, error)
	// GenerateSingleKey generates a key on demand if there is no key in the pool.
	GenerateSingleKey(ctx context.Context, logger logrus.Entry) (*rsa.PrivateKey, error)

	// BlockUntilCount blocks until the keypool contains the number of keys required.
	// returns nil when the count is reached
	// if count > capacity: will block until the capacity of the pool is reached
	// if count is 0: will not block at all
	// returns a wrapped context error if the context deadline is exceeded or if the context is canceled.
	BlockUntilCount(ctx context.Context, logger logrus.Entry, count int) error
}

type KeyGenerator interface {
	GenerateKey(length int) (*rsa.PrivateKey, error)
}
