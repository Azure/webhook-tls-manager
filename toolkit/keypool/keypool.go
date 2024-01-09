package keypool

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const KeySize = 4096

var workerTickerInterval = time.Second * 5
var ErrEmptyPool = errors.New("key pool is empty")

type KeyPool struct {
	workerNumber   int64
	maxConcurrency func() int64
	pool           chan *rsa.PrivateKey
}

func (k *KeyPool) CurrentSize() int { return len(k.pool) }

func NewKeyPool(maxPoolSize int,
	maxConcurrency func() int64) *KeyPool {
	return &KeyPool{
		pool:           make(chan *rsa.PrivateKey, maxPoolSize),
		maxConcurrency: maxConcurrency,
	}
}

func (k *KeyPool) BlockUntilCount(ctx context.Context, logger logrus.Entry, count int) error {
	_, ok := ctx.Deadline()
	if !ok {
		logger.Warning(ctx, "Blocking on keypool without a context deadline!")
	}
	if count == 0 {
		logger.Warning(ctx, "Block Until 0. We will not wait at all")
		return nil
	}
	if count > cap(k.pool) {
		logger.Warning(ctx, "count is larger than pool capacity, using pool capacity instead")
		count = cap(k.pool)
	}
	logger.Infof("Waitig for pool to reach %d. current pool size: %d", count, k.CurrentSize())
	interval := 100 * time.Millisecond
	if count <= k.CurrentSize() {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("requested count (%d) was not reached in allocated time. Current count: %d: %w", count, k.CurrentSize(), ctx.Err())
		case <-time.After(interval):
			if count <= k.CurrentSize() {
				return nil
			}
		}
	}
}

func (k *KeyPool) GetKey(ctx context.Context, logger logrus.Entry) (*rsa.PrivateKey, error) {
	logger.Infof("getting key from key pool")

	select {
	case key, ok := <-k.pool:
		if !ok {
			logger.Error("key pool is shutting down")
			return nil, ErrEmptyPool
		}

		logger.Infof("successfully got key from key pool with %d remaining keys", len(k.pool))
		return key, nil
	default:
		logger.Error("no keys are available in the key pool")
		return nil, ErrEmptyPool
	}
}

func (k *KeyPool) GenerateSingleKey(ctx context.Context, logger logrus.Entry) (*rsa.PrivateKey, error) {
	logger.Infof("It is entering into the single key generation phase")
	start := time.Now()

	keySizeInUse := KeySize

	privateKey, err := GenerateKey(keySizeInUse)
	if err != nil {
		return nil, err
	}

	ts := time.Since(start).Seconds()
	logger.Infof("Generated single key in '%5f' seconds", ts)
	return privateKey, nil
}

func (k *KeyPool) Run(ctx context.Context, logger logrus.Entry) {
	var wg sync.WaitGroup

	defer func() {
		close(k.pool)
		logger.Infof("[keypool] shut down successfully")
	}()

	// Log the pool size periodically
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second * 5)

		for {
			select {
			case <-ticker.C:
				logger.Infof("[keypool] current pool size: %d", k.CurrentSize())
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start key generation loops
	logger.Infof("[keypool] starting key generation loops")
	ticker := time.NewTicker(workerTickerInterval)
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			logger.Infof("waiting for other go routine completing")
			wg.Wait()
			logger.Infof("all go routine completed")
			return
		}
		if atomic.LoadInt64(&k.workerNumber) < k.maxConcurrency() {
			id := atomic.AddInt64(&k.workerNumber, 1)
			wg.Add(1)
			go func(id int64) {
				defer wg.Done()
				logger.Infof("[keypool loop %d] starting loop", id)
				k.keyGenerationLoop(ctx, logger, id)
				logger.Infof("[keypool loop %d] loop shut down", id)
			}(id)
		}
	}
}

func (k *KeyPool) keyGenerationLoop(ctx context.Context, logger logrus.Entry, loopID int64) {
	defer func() {
		workerNumber := atomic.AddInt64(&k.workerNumber, -1)
		logger.Infof("workerNumber is %v", workerNumber)
		r := recover()
		if r != nil {
			logger.Errorf("[keypool loop %d] caught panic: %v", loopID, r)
		}
	}()

	for {
		if loopID > k.maxConcurrency() {
			logger.Infof("[keypool loop %d] is larger than %d, exiting...", loopID, k.maxConcurrency())
			return
		}

		logger.Infof("[keypool loop %d] generating key", loopID)

		start := time.Now()

		keySizeInUse := KeySize

		privateKey, err := GenerateKey(keySizeInUse)
		if err != nil {
			logger.Errorf("[keypool loop %d] error generating key for pool: %v", loopID, err)
			time.Sleep(time.Millisecond * 50) // Wait a bit to prevent possible tightloop
			continue
		}

		ts := time.Since(start).Seconds()
		logger.Infof("[keypool loop %d] generated key in '%.3f's", loopID, ts)

		select {
		case k.pool <- privateKey:
		case <-ctx.Done():
			logger.Infof("[keypool loop %d] shutting down...", loopID)
			return
		}
	}
}
