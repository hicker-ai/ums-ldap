// Package logs provides structured logging with console/file output and rotation.
package logs

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// OutFile holds file rotation configuration.
type OutFile struct {
	Enabled    bool   `mapstructure:"enabled"`
	OutputPath string `mapstructure:"output_path"`
	MaxSize    int    `mapstructure:"max_size"`    // MB
	MaxAge     int    `mapstructure:"max_age"`     // days
	MaxBackups int    `mapstructure:"max_backups"` // maximum number of old log files to retain
	Compress   bool   `mapstructure:"compress"`    // gzip
	LocalTime  bool   `mapstructure:"local_time"`  // use local time for timestamps instead of UTC
}

// Format represents log output format.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// Config holds logging configuration.
type Config struct {
	Console   bool   `mapstructure:"console"`
	AddSource bool   `mapstructure:"add_source"`
	Level     string `mapstructure:"level"`
	Format    Format `mapstructure:"format"`
	Rotate    OutFile `mapstructure:"rotate"`
}

var (
	logger *zap.Logger
	once   sync.Once
)

// Init initializes the global logger. Safe to call multiple times; only the first call takes effect.
func Init(c Config) {
	once.Do(func() {
		logger = build(c)
	})
}

func build(c Config) *zap.Logger {
	encConfig := zap.NewProductionEncoderConfig()
	encConfig.TimeKey = "dt"
	encConfig.MessageKey = "msg"
	encConfig.CallerKey = "caller"
	encConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	var encoder zapcore.Encoder
	if c.Format == FormatJSON {
		encoder = zapcore.NewJSONEncoder(encConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encConfig)
	}

	if c.Level == "" {
		c.Level = "info"
	}

	opts := []zap.Option{
		zap.AddCallerSkip(0),
		zap.AddStacktrace(zap.ErrorLevel),
	}
	if c.AddSource {
		opts = append(opts, zap.AddCaller())
		encConfig.EncodeCaller = zapcore.ShortCallerEncoder
	}

	var mws []zapcore.WriteSyncer

	// File rotation
	if c.Rotate.Enabled {
		outputPath := c.Rotate.OutputPath
		if outputPath == "" {
			outputPath = "./logs"
		}

		hostname, _ := os.Hostname()
		fn := fmt.Sprintf("%s/%s~%s.log", outputPath, hostname, time.Now().Format("2006-01-02_15-04-05"))

		rotateCfg := &lumberjack.Logger{
			Filename:   fn,
			MaxSize:    100,
			MaxAge:     7,
			MaxBackups: 3,
			Compress:   false,
			LocalTime:  false,
		}
		if c.Rotate.MaxSize > 0 {
			rotateCfg.MaxSize = c.Rotate.MaxSize
		}
		if c.Rotate.MaxAge > 0 {
			rotateCfg.MaxAge = c.Rotate.MaxAge
		}
		if c.Rotate.MaxBackups > 0 {
			rotateCfg.MaxBackups = c.Rotate.MaxBackups
		}
		if c.Rotate.Compress {
			rotateCfg.Compress = true
		}
		if c.Rotate.LocalTime {
			rotateCfg.LocalTime = true
		}
		mws = append(mws, zapcore.AddSync(rotateCfg))
	}

	// Console
	if c.Console {
		mws = append(mws, zapcore.AddSync(os.Stdout))
	}

	mw := zapcore.NewMultiWriteSyncer(mws...)

	// Level
	level := zap.InfoLevel
	switch c.Level {
	case "debug":
		level = zap.DebugLevel
	case "warn":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	case "fatal":
		level = zap.FatalLevel
	}

	core := zapcore.NewCore(encoder, mw, level)
	return zap.New(core, opts...)
}

// Logger returns the global logger. If not initialized, returns a default console logger.
func Logger() *zap.Logger {
	if logger == nil {
		return zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			zapcore.AddSync(os.Stdout),
			zap.DebugLevel,
		))
	}
	return logger
}

// Debug logs a message at DebugLevel.
func Debug(msg string, fields ...zapcore.Field) {
	Logger().Debug(msg, fields...)
}

// Info logs a message at InfoLevel.
func Info(msg string, fields ...zapcore.Field) {
	Logger().Info(msg, fields...)
}

// Warn logs a message at WarnLevel.
func Warn(msg string, fields ...zapcore.Field) {
	Logger().Warn(msg, fields...)
}

// Error logs a message at ErrorLevel.
func Error(msg string, fields ...zapcore.Field) {
	Logger().Error(msg, fields...)
}
