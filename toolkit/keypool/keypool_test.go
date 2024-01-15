package keypool

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/Azure/webhook-tls-manager/toolkit/keypool/mock_key_generator"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
)

var maxConcurrency int64
var _ = Describe("key pool", func() {
	var (
		ctx     context.Context
		cancel  context.CancelFunc
		pool    *KeyPool
		mockKey *rsa.PrivateKey
		logger  logrus.Entry
	)
	mockKey, _ = rsa.GenerateKey(rand.Reader, 2048)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background()) // nolint
		logger = *log.NewLogger(ctx)
	}) // nolint

	AfterEach(func() {
		cancel()
	})

	When("given a fake key generation function", func() {
		When("configured for one worker, one key", func() {
			var (
				maxPoolSize = 1
			)
			BeforeEach(func() {
				atomic.StoreInt64(&maxConcurrency, 1)
			})
			When("should eventually return the fake generated key", func() {
				AfterEach(func() {
					cancel()
					Eventually(func() bool {
						_, ok := <-pool.pool
						return ok
					}, time.Minute, time.Millisecond*100).Should(BeFalse())
				})
				FIt("should eventually return the fake generated key", func() {
					f1 := func(bits int) (*rsa.PrivateKey, error) {
						return mockKey, nil
					}

					mockCtrl := gomock.NewController(GinkgoT())
					keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
					keyGenerator.EXPECT().GenerateKey(gomock.Any()).DoAndReturn(f1).AnyTimes()

					pool = NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)
					go pool.Run(ctx, logger)

					actual := waitForKey(ctx, logger, pool)
					fmt.Printf("actual N: %v\n", actual.N)
					fmt.Printf("mockKey: %v\n", mockKey.N)
					Expect(actual == mockKey).To(BeTrue())
				})
			})

			When("loop isn't running", func() {
				It("should return ErrEmptyPool", func() {
					mockCtrl := gomock.NewController(GinkgoT())
					keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
					pool = NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)

					_, err := pool.GetKey(ctx, logger)
					Expect(err).To(Equal(ErrEmptyPool))
				})

				It("should return succeed if GenerateKey succeeds", func() {
					mockCtrl := gomock.NewController(GinkgoT())
					keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
					pool = NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)
					keyGenerator.EXPECT().GenerateKey(4096).Return(mockKey, nil).AnyTimes()

					privateKey, err := pool.GenerateSingleKey(ctx, logger)
					Expect(err).To(BeNil())
					Expect(privateKey).NotTo(BeNil())
				})

				It("should return error if GenerateKey fails", func() {
					mockCtrl := gomock.NewController(GinkgoT())
					keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
					pool = NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)
					keyGenerator.EXPECT().GenerateKey(4096).Return(nil, fmt.Errorf("random error"))

					privateKey, err := pool.GenerateSingleKey(ctx, logger)
					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(Equal("random error"))
					Expect(privateKey).To(BeNil())
				})
			})

			When("genfunc panics", func() {
				It("should recover", func() {
					f1 := func(bits int) (*rsa.PrivateKey, error) {
						panic("boom!")
					}

					mockCtrl := gomock.NewController(GinkgoT())
					keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
					keyGenerator.EXPECT().GenerateKey(gomock.Any()).DoAndReturn(f1).Times(1)
					keyGenerator.EXPECT().GenerateKey(gomock.Any()).Return(mockKey, nil).AnyTimes()

					pool = NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)
					go pool.Run(ctx, logger)

					// It should recover eventually
					actual := waitForKey(ctx, logger, pool)
					Expect(actual).ToNot(BeNil())
				})
			})

			When("genfunc returns an error", func() {
				It("should recover", func() {
					f1 := func(bits int) (*rsa.PrivateKey, error) {
						return nil, errors.New("test key generation errors")
					}
					mockCtrl := gomock.NewController(GinkgoT())
					keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
					keyGenerator.EXPECT().GenerateKey(gomock.Any()).DoAndReturn(f1).Times(1)
					keyGenerator.EXPECT().GenerateKey(gomock.Any()).Return(mockKey, nil).AnyTimes()

					pool = NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)
					go pool.Run(ctx, logger)

					// It should recover eventually
					actual := waitForKey(ctx, logger, pool)
					Expect(actual).ToNot(BeNil())
				})
			})

			When("the context is canceled", func() {
				It("should stop all worker routines", func() {
					mockCtrl := gomock.NewController(GinkgoT())
					keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
					pool = NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)
					keyGenerator.EXPECT().GenerateKey(gomock.Any()).Return(mockKey, nil).AnyTimes()
					go pool.Run(ctx, logger)

					// Wait for a key to be generated
					waitForKey(ctx, logger, pool)

					// Stop the loops
					cancel()

					// Prove loops stop eventually
					Eventually(func() error {
						_, err := pool.GetKey(ctx, logger)
						return err
					}).Should(Equal(ErrEmptyPool))
				})
			})
		})
	})

	When("configured for 2 workers, 3 keys", func() {
		var (
			maxPoolSize = 3
		)

		BeforeEach(func() {
			atomic.StoreInt64(&maxConcurrency, 2)
		})

		It("should eventually return three distinct keys [slow]", func() {
			//workerTickerInterval = time.Microsecond
			privateKeyArray := []*rsa.PrivateKey{
				{
					PublicKey: rsa.PublicKey{
						E: 1,
					},
				},
				{
					PublicKey: rsa.PublicKey{
						E: 2,
					},
				},
				{
					PublicKey: rsa.PublicKey{
						E: 3,
					},
				},
			}
			f1 := func(bits int) (*rsa.PrivateKey, error) {
				return &rsa.PrivateKey{}, nil
			}

			mockCtrl := gomock.NewController(GinkgoT())
			keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
			gomock.InOrder(
				keyGenerator.EXPECT().GenerateKey(gomock.Any()).Return(privateKeyArray[0], nil).Times(1),
				keyGenerator.EXPECT().GenerateKey(gomock.Any()).Return(privateKeyArray[1], nil).Times(1),
				keyGenerator.EXPECT().GenerateKey(gomock.Any()).Return(privateKeyArray[2], nil).Times(1),
				keyGenerator.EXPECT().GenerateKey(gomock.Any()).DoAndReturn(f1).AnyTimes(),
			)

			pool := NewKeyPool(maxPoolSize, getMaxConcurrency, keyGenerator)
			go pool.Run(ctx, logger)

			// Wait for keys to be generated
			Eventually(pool.CurrentSize, time.Minute).Should(Equal(maxPoolSize))

			// Prove the three keys are distinct
			var keys []*rsa.PrivateKey
			for i := 0; i < 3; i++ {
				key, err := pool.GetKey(ctx, logger)
				Expect(err).ToNot(HaveOccurred())
				Expect(key).ToNot(BeNil())
				Expect(keys).ToNot(ContainElement(key))
				keys = append(keys, key)
			}
		})

		It("Worker number should increase & drop", func() {
			mockCtrl := gomock.NewController(GinkgoT())
			keyGenerator := mock_key_generator.NewMockKeyGenerator(mockCtrl)
			keyGenerator.EXPECT().GenerateKey(gomock.Any()).Return(mockKey, nil).AnyTimes()

			pool = NewKeyPool(100000, getMaxConcurrency, keyGenerator)
			go pool.Run(ctx, logger)

			// Wait for worker number increase to 2
			Eventually(func() bool {
				return atomic.LoadInt64(&pool.workerNumber) == 2
			}, time.Minute, time.Millisecond*1).Should(BeTrue())

			atomic.StoreInt64(&maxConcurrency, 0)
			// Wait for worker number drop to 0
			Eventually(func() bool {
				return atomic.LoadInt64(&pool.workerNumber) == 0
			}, time.Minute, time.Millisecond*1).Should(BeTrue())
		})
	})

	Describe("BlockUntilCount", func() {
		ctx := context.Background()
		DescribeTable("key count",
			func(entryCtx context.Context, currentSize, capacity int, blockUntil int, expectError error) {
				timeout := 60 * time.Millisecond
				k := NewKeyPool(capacity, getMaxConcurrency, nil)
				for i := 0; i < currentSize; i++ {
					k.pool <- &rsa.PrivateKey{}
				}
				entryCtx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				err := k.BlockUntilCount(entryCtx, logger, blockUntil)
				if expectError != nil {
					Expect(err).To(And(HaveOccurred()))
					Expect(errors.Is(err, context.DeadlineExceeded)).To(BeTrue(), "expected error to be of type deadlineExceeded but got: %s", err)
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
			},
			Entry("achieved 1/1", ctx, 1, 1, 1, nil),
			Entry("achieved 0/0", ctx, 0, 0, 0, nil),
			Entry("achieved 1/2", ctx, 1, 2, 1, nil),
			Entry("not achieved DeadlineExceeded 1/3", ctx, 1, 3, 2, context.DeadlineExceeded),
			Entry("count over capacity with full pool", ctx, 3, 3, 4, nil),
			Entry("count over capacity with pool not full", ctx, 2, 3, 4, context.DeadlineExceeded),
		)
	})
})

func waitForKey(ctx context.Context, logger logrus.Entry, pool Interface) *rsa.PrivateKey {
	var actual *rsa.PrivateKey

	Eventually(func() (err error) {
		actual, err = pool.GetKey(ctx, logger)
		return err
	}, time.Minute, time.Millisecond*100).ShouldNot(HaveOccurred())

	return actual
}

func getMaxConcurrency() int64 { return atomic.LoadInt64(&maxConcurrency) }
