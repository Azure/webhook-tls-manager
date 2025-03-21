package log

import (
	"context"
	"crypto/rand"
	"runtime"

	"github.com/sirupsen/logrus"

	otelTrace "go.opentelemetry.io/otel/trace"
)

const (
	upperCaseAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	epochFieldName        = "env_epoch"
	fileNameFieldName     = "fileName"
	lineNumberFieldName   = "lineNumber"
)

type Logger struct {
	logger *logrus.Entry
}

type loggerKeyType string

const loggerKey loggerKeyType = "web-tls-manager"

func (logger *Logger) WithLogger(ctx context.Context) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func MustGetLogger(ctx context.Context) *Logger {
	logger, loggerFound := ctx.Value(loggerKey).(*Logger)
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

func NewLogger(loggerLevel int) *Logger {
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
	return &Logger{logger: logger.WithField(epochFieldName, epoch)}
}

func (logger *Logger) withCallerInfo() *logrus.Entry {
	_, file, line, _ := runtime.Caller(3)
	fields := make(map[string]interface{})
	fields[fileNameFieldName] = file
	fields[lineNumberFieldName] = line
	return logger.logger.WithFields(fields)
}

func GetOtelSpanFromContext(ctx context.Context) Span {
	span := otelTrace.SpanFromContext(ctx)
	return &otelSpan{span: span}
}

func (logger *Logger) withSpanInfo(ctx context.Context) *Logger {
	if ctx == nil {
		return logger
	}

	span := GetOtelSpanFromContext(ctx)
	if !span.IsValid() {
		return logger
	}
	logrusLogger := logger.logger.WithFields(map[string]interface{}{
		"spanID":  span.GetSpanID(),
		"traceID": span.GetTraceID(),
	})
	return &Logger{logrusLogger}
}

func (logger *Logger) Info(ctx context.Context, msg string) {
	logger.withSpanInfo(ctx).withCallerInfo().Info(msg)
}

func (logger *Logger) Infof(ctx context.Context, fmt string, args ...interface{}) {
	logger.withSpanInfo(ctx).withCallerInfo().Infof(fmt, args...)
}

func (logger *Logger) Error(ctx context.Context, msg string) {
	logger.withSpanInfo(ctx).withCallerInfo().Error(msg)
}

func (logger *Logger) Errorf(ctx context.Context, fmt string, args ...interface{}) {
	logger.withSpanInfo(ctx).withCallerInfo().Errorf(fmt, args...)
}

func (logger *Logger) Warning(ctx context.Context, msg string) {
	logger.withSpanInfo(ctx).withCallerInfo().Error(msg)
}

func (logger *Logger) Warningf(ctx context.Context, fmt string, args ...interface{}) {
	logger.withSpanInfo(ctx).withCallerInfo().Warningf(fmt, args...)
}

func (logger *Logger) Debugf(ctx context.Context, fmt string, args ...interface{}) {
	logger.withSpanInfo(ctx).withCallerInfo().Debugf(fmt, args...)
}
