package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

/**
* Global logger
 */
var sugar *zap.SugaredLogger
var logRequests bool
var skipPaths []string

// logging config
type LoggingConfig struct {
	// loglevel to be used - can be DEBUG, INFO, WARN or ERROR
	Level string `mapstructure:"level" default:"INFO"`
	// should the logging in a structured json format
	JsonLogging bool `mapstructure:"jsonLogging" default:"true"`
	// should requests be logged
	LogRequests bool `mapstructure:"logRequests" default:"true"`
	// list of paths to be ignored on request logging(could be often called operational endpoints like f.e. metrics)
	PathsToSkip []string `mapstructure:"pathsToSkip"`
}

/**
* Initialize the global logger with default values. This will be overridden by the Configure method,
* but ensures that we have a logger available even if Configure is not called.
**/
func init() {
	conf := zap.NewProductionConfig()
	l, _ := conf.Build()
	sugar = l.Sugar()
}

/**
* Apply the given configuration to the global logger.
**/
func Configure(logConfig LoggingConfig) {

	var config zap.Config
	if logConfig.JsonLogging {
		config = zap.NewProductionConfig()
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	var level zapcore.Level
	levelErr := level.Set(logConfig.Level)
	if levelErr != nil {
		level = zapcore.InfoLevel
	}

	config.Level = zap.NewAtomicLevelAt(level)
	logger, _ := config.Build()
	sugar = logger.Sugar()

	if levelErr != nil {
		sugar.Warnf("Invalid log level %v, defaulting to INFO", logConfig.Level)
	}
	logRequests = logConfig.LogRequests
	skipPaths = logConfig.PathsToSkip
}

/**
*  Global access to the singleton logger
**/
func Log() *zap.SugaredLogger {
	return sugar
}

/**
* Gin compatible function to enable logger injection into the gin-framework
**/
func GinHandlerFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !logRequests {
			c.Next()
			return
		}
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		if raw != "" {
			path = path + "?" + raw
		}

		// Process request
		c.Next()

		if slices.Contains(skipPaths, path) {
			return
		}

		// Stop timer
		latency := time.Since(start).Seconds() * 1000
		statusCode := c.Writer.Status()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()
		request := fmt.Sprintf("%s %s %s", c.Request.Method, c.Request.URL.RequestURI(), c.Request.Proto)
		size := c.Writer.Size()

		if errorMessage != "" {
			Log().Warnf("Request \"%s\" %d (%d) - %.3fms. Error %s", request, statusCode, size, latency, errorMessage)
		} else {
			Log().Infof("Request \"%s\" %d (%d) - %.3fms", request, statusCode, size, latency)
		}
	}
}

/**
* Helper method to print objects with json-serialization information in a more human readable way
 */
func PrettyPrintObject(objectInterface interface{}) string {
	jsonBytes, err := json.Marshal(objectInterface)
	if err != nil {
		Log().Debugf("Was not able to pretty print the object: %v", objectInterface)
		return ""
	}
	return string(jsonBytes)
}

type zapWriterFunc func(p []byte) (n int, err error)

func (f zapWriterFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

func GetGinInternalWriter() io.Writer {
	return zapWriterFunc(func(p []byte) (n int, err error) {
		msg := string(p)
		cleanMsg := strings.TrimSpace(msg)

		if cleanMsg == "" {
			return len(p), nil
		}

		switch {
		case strings.Contains(msg, "[ERROR]"):
			sugar.Error(cleanMsg)
		case strings.Contains(msg, "[WARNING]"):
			sugar.Warn(cleanMsg)
		default:
			sugar.Info(cleanMsg)
		}

		return len(p), nil
	})
}
