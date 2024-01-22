package certgenerator

// import (
// 	"context"
// 	"crypto/rand"
// 	"crypto/rsa"
// 	"errors"

// 	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certcreator/mock_cert_creator"
// 	"github.com/Azure/webhook-tls-manager/toolkit/keypool/mock_keypool"
// 	"github.com/Azure/webhook-tls-manager/toolkit/log"
// 	"github.com/golang/mock/gomock"
// 	. "github.com/onsi/ginkgo"
// 	. "github.com/onsi/gomega"
// 	"github.com/sirupsen/logrus"
// )

// var _ = Describe("CertGenerator", func() {
// 	var (
// 		ctx             context.Context
// 		logger          *logrus.Entry
// 		privateKey      *rsa.PrivateKey
// 		mockCertCreator *mock_cert_creator.MockCertCreator
// 		mockKeyPool     *mock_keypool.MockInterface
// 		mockCtrl        *gomock.Controller
// 	)

// 	BeforeEach(func() {
// 		mockCtrl = gomock.NewController(GinkgoT())
// 		mockCertCreator = mock_cert_creator.NewMockCertCreator(mockCtrl)
// 		mockKeyPool = mock_keypool.NewMockInterface(mockCtrl)
// 		logger = log.NewLogger(context.Background())
// 		ctx = log.WithLogger(context.Background(), logger)
// 		privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
// 	})

// 	// It("ensureHasKey succeed: keypool has key", func() {
// 	// 	mockKeyPool.EXPECT().GetKey(ctx, gomock.Any()).Return(privateKey, nil)
// 	// 	certGenerator := NewCertGenerator(mockKeyPool, mockCertCreator)
// 	// 	k, err := certGenerator.(*certificateGeneratorImp).ensureHasKey(ctx, logger)
// 	// 	Expect(err).To(BeNil())
// 	// 	Expect(k).NotTo(BeNil())
// 	// })

// 	// It("ensureHasKey succeed: keypool doesn't have key", func() {
// 	// 	mockKeyPool.EXPECT().GetKey(ctx, gomock.Any()).Return(nil, errors.New("key not found"))
// 	// 	mockKeyPool.EXPECT().GenerateSingleKey(ctx, gomock.Any()).Return(privateKey, nil)
// 	// 	mockKeyPool.EXPECT().CurrentSize().Return(0)
// 	// 	certGenerator := NewCertGenerator(mockKeyPool, mockCertCreator)
// 	// 	k, err := certGenerator.(*certificateGeneratorImp).ensureHasKey(ctx, logger)
// 	// 	Expect(err).To(BeNil())
// 	// 	Expect(k).NotTo(BeNil())
// 	// })
// })
