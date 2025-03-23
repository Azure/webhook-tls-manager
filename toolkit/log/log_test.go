package log

import (
	"bytes"
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe(
	"Logger functionality",
	func() {
		Context("WithSpanInfo", func() {
			var (
				baseLogger *logrus.Logger
				logger     *Logger
			)

			BeforeEach(func() {
				baseLogger = logrus.New()
				logger = &Logger{logger: logrus.NewEntry(baseLogger)}
			})

			BeforeEach(func() {
				baseLogger = logrus.New()
				logger = &Logger{logger: logrus.NewEntry(baseLogger)}
			})

			It("returns the same logger when context is nil", func() {
				result := logger.withSpanInfo(nil)
				Expect(result).To(BeIdenticalTo(logger))
			})

			It("returns the same logger when span is invalid", func() {
				ctx := context.Background() // no span in context
				result := logger.withSpanInfo(ctx)
				Expect(result).To(BeIdenticalTo(logger))
			})

		})

		It("NewLogger", func() {
			logger := NewLogger(3)
			ctx := logger.WithLogger(context.Background())
			buf := &bytes.Buffer{}
			logger.logger.Logger.SetOutput(buf)
			logger.Info(ctx, "test")
			fmt.Print(buf.String())
			Expect(buf.String()).To(ContainSubstring("test"))
		})

		It("context with logger", func() {
			logger := NewLogger(3)
			ctx := logger.WithLogger(context.Background())
			Expect(ctx).NotTo(BeNil())
			logger = MustGetLogger(ctx)
			buf := &bytes.Buffer{}
			logger.logger.Logger.SetOutput(buf)
			logger.Error(ctx, "test")
			fmt.Print(buf.String())
			Expect(buf.String()).To(ContainSubstring("test"))
		})
	},
)
