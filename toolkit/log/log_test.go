package log

import (
	"bytes"
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	// . "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe(
	"Logger functionality",
	func() {
		It("NewLogger", func() {
			logger := NewLogger(context.Background())
			buf := &bytes.Buffer{}
			logger.Logger.SetOutput(buf)
			logger.Info("test")
			fmt.Print(buf.String())
			Expect(buf.String()).To(ContainSubstring("test"))
		})

		It("context with logger", func() {
			logger := NewLogger(context.Background())
			ctx := WithLogger(context.Background(), logger)
			Expect(ctx).NotTo(BeNil())
			logger = MustGetLogger(ctx)
			buf := &bytes.Buffer{}
			logger.Logger.SetOutput(buf)
			logger.Error("test")
			fmt.Print(buf.String())
			Expect(buf.String()).To(ContainSubstring("test"))
		})
	},
)
