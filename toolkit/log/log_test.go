package log

import (
	"bytes"
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(
	"Logger functionality",
	func() {
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
