package logger

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/0x726f6f6b6965/go-auth/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Log is global logger
	rootLogger *zap.Logger

	// timeFormat is custom Time format
	customTimeFormat string

	// onceInitLogger guarantee initialize logger only once
	onceInitLogger sync.Once
)

// NewLogger create logger using zap implementation
// The return signature (logger, cleanup function and error) is dictated by the fact that this function is used by wire.
func NewLogger(cfg *config.LogConfig) (*zap.Logger, func(), error) {
	level := 1 // default is warn
	timeFormat := "2006-01-02T15:04:05Z07:00"
	timestampEnabled := false
	serviceName := "???service???"

	if cfg != nil {
		level = cfg.Level
		timeFormat = cfg.TimeFormat
		timestampEnabled = cfg.TimestampEnabled

		if len(cfg.ServiceName) > 0 {
			serviceName = cfg.ServiceName
		}
	}

	if err := initZapLogger(level, timeFormat, timestampEnabled, serviceName); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize logger: %v", err)
	}

	return rootLogger, func() {}, nil
}

// customTimeEncoder encode Time to our custom format
// This example how we can customize zap default functionality
func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format(customTimeFormat))
}

// Encode log message levels with desired abbreviations (all the same length for improved readability).
func customLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	if level == zap.DebugLevel {
		enc.AppendString("DBG")
	} else if level == zap.InfoLevel {
		enc.AppendString("INF")
	} else if level == zap.WarnLevel {
		enc.AppendString("WRN")
	} else if level == zap.ErrorLevel {
		enc.AppendString("ERR")
	} else if level == zap.DPanicLevel || level == zap.PanicLevel || level == zap.FatalLevel {
		enc.AppendString("CRT")
	} else {
		enc.AppendString("???")
	}
}

// Init initializes log by input parameters
// lvl - global log level: Debug(-1), Info(0), Warn(1), Error(2), DPanic(3), Panic(4), Fatal(5)
// timeFormat - custom time format for logger of empty string to use default
// timestampEnabled - enables timestamp in log
// serviceName - name of the service that we are a part of
func initZapLogger(lvl int, timeFormat string, timestampEnabled bool, serviceName string) error {
	var err error

	onceInitLogger.Do(func() {
		// First, define our level-handling logic.
		globalLevel := zapcore.Level(lvl)

		// High-priority output should also go to standard error, and low-priority
		// output should also go to standard out.
		// It is usefull for Kubernetes deployment.
		// Kubernetes interprets os.Stdout log items as INFO and os.Stderr log items
		// as ERROR by default.
		highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl >= zapcore.ErrorLevel
		})
		lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl >= globalLevel && lvl < zapcore.ErrorLevel
		})
		consoleInfos := zapcore.Lock(os.Stdout)
		consoleErrors := zapcore.Lock(os.Stderr)

		// Configure console output.
		var useCustomTimeFormat bool
		ecfg := zap.NewProductionEncoderConfig()
		if len(timeFormat) > 0 {
			customTimeFormat = timeFormat
			ecfg.EncodeTime = customTimeEncoder
			useCustomTimeFormat = true
		}

		// Conditionally exclude timestamp (when used in real system, syslog will provide timestamp)
		if !timestampEnabled {
			ecfg.TimeKey = ""
		}

		// these keys are chosen to be consistent with the Python logger that we are using elsewhere
		ecfg.CallerKey = "src"
		ecfg.MessageKey = "msg"
		ecfg.LevelKey = "lvl"
		ecfg.NameKey = "id"

		// Use custom level encoder to match our Python logger
		ecfg.EncodeLevel = customLevelEncoder

		consoleEncoder := zapcore.NewJSONEncoder(ecfg)

		// Join the outputs, encoders, and level-handling functions into
		// zapcore.
		core := zapcore.NewTee(
			zapcore.NewCore(consoleEncoder, consoleErrors, highPriority),
			zapcore.NewCore(consoleEncoder, consoleInfos, lowPriority),
		)

		// Create logger, with caller option (identifies the file and line number of the caller)
		rootLogger = zap.New(core, zap.AddCaller())

		// Give the logger a name, consisting of the organization name and service name.
		rootLogger = rootLogger.Named(serviceName)

		// RedirectStdLog redirects output from the standard library's package-global logger to the supplied logger at
		// InfoLevel. Since zap already handles caller annotations, timestamps, etc., it automatically disables the
		// standard library's annotations and prefixing.
		zap.RedirectStdLog(rootLogger)

		if !useCustomTimeFormat {
			rootLogger.Warn("time format for logger is not provided - use zap default")
		}
	})

	return err
}
