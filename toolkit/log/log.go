package log

import (
	"context"
	"crypto/rand"

	"github.com/sirupsen/logrus"
)

const (
	upperCaseAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	epochFieldName        = "env_epoch"
)

type loggerKeyType string

const loggerKey loggerKeyType = "web-tls-manager"

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

func NewLogger(ctx context.Context, loggerLevel int) *logrus.Entry {
	logger := logrus.New()
	switch loggerLevel {
	case 4:
		logger.SetLevel(logrus.DebugLevel)
	case 5:
		logger.SetLevel(logrus.TraceLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}
	logger.Formatter = &logrus.JSONFormatter{}
	epoch, _ := getEpochRandomString()
	return logger.WithField(epochFieldName, epoch)
}
