package log

import (
	"context"
	"crypto/rand"

	"github.com/sirupsen/logrus"
)

const (
	loggerKey             = "web-tls-manager"
	upperCaseAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	epochFieldName        = "env_epoch"
)

func WithLogger(ctx context.Context, logger *logrus.Entry) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func MustGetLogger(ctx context.Context) *logrus.Entry {
	logger, loggerFound := ctx.Value(loggerKey).(*logrus.Entry)
	if !loggerFound {
		panic("Logger not found in context. Use WithLogger(ctx, logger) to create a context with a logger")
	}
	return logger
}

func getEpochRandomString() (string, error) {
	randomBytes := make([]byte, 5)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	for index, randomByte := range randomBytes {
		foldedOffset := randomByte % byte(len(upperCaseAlphanumeric))
		randomBytes[index] = upperCaseAlphanumeric[foldedOffset]
	}
	return string(randomBytes), nil
}

func NewLogger(ctx context.Context) *logrus.Entry {
	logger := logrus.New()
	logger.Formatter = &logrus.JSONFormatter{}
	epoch, _ := getEpochRandomString()
	return logger.WithField(epochFieldName, epoch)
}
