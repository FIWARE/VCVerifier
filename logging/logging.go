package logging

import (
	"encoding/json"
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

	switch strings.ToUpper(logConfig.Level) {
	case "DEBUG":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "INFO":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "WARN":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "ERROR":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, _ := config.Build()
	sugar = logger.Sugar()

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
		latency := time.Since(start)
		method := c.Request.Method
		statusCode := c.Writer.Status()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		if errorMessage != "" {
			Log().Warnf("Request [%s]%s took %d ms - Result: %d - %s", method, path, latency, statusCode, errorMessage)
		} else {
			Log().Infof("Request [%s]%s took %d ms - Result: %d", method, path, latency, statusCode)
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
