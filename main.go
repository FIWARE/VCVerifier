package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	configModel "github.com/fiware/VCVerifier/config"
	logging "github.com/fiware/VCVerifier/logging"
	api "github.com/fiware/VCVerifier/openapi"
	"github.com/fiware/VCVerifier/verifier"

	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/penglongli/gin-metrics/ginmetrics"
)

// default config file location - can be overwritten by envvar
var configFile string = "server.yaml"

/**
* Startup method to run the gin-server.
 */
func main() {

	configuration, err := configModel.ReadConfig(configFile)
	if err != nil {
		panic(err)
	}

	logging.Configure(configuration.Logging)

	logger := logging.Log()

	logger.Infof("Configuration is: %s", logging.PrettyPrintObject(configuration))

	verifier.InitVerifier(&configuration)
	verifier.InitPresentationParser(&configuration, Health())

	router := getRouter()

	// health check
	router.GET("/health", HealthReq)

	allowedOrigins := ResolveAllowedOrigins(configuration.ConfigRepo.Services)
	logger.Infof("CORS allowed origins: %v", allowedOrigins)

	router.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"POST", "GET"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	//new template engine
	router.HTMLRender = ginview.Default()
	// static files for the frontend
	router.Static("/static", configuration.Server.StaticDir)

	templateDir := configuration.Server.TemplateDir
	if templateDir != "" {
		if strings.HasSuffix(templateDir, "/") {
			templateDir = templateDir + "*.html"
		} else {
			templateDir = templateDir + "/*.html"
		}
		logging.Log().Infof("Intialize templates from %s", templateDir)
		router.LoadHTMLGlob(templateDir)
	}

	// initiate metrics
	metrics := ginmetrics.GetMonitor()
	metrics.SetMetricPath("/metrics")
	metrics.Use(router)

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%v", configuration.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(configuration.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(configuration.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(configuration.Server.IdleTimeout) * time.Second,
	}

	// Start the server in a goroutine so it doesn't block
	go func() {
		logging.Log().Infof("Starting server on port %v", configuration.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Log().Errorf("Failed to start server: %v", err)
			os.Exit(1)
		}
	}()

	// --- Graceful Shutdown Logic ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	logging.Log().Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(configuration.Server.ShutdownTimeout)*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logging.Log().Errorf("Server forced to shutdown: %v", err)
	}

	logging.Log().Info("Server exiting gracefully")
}

// initiate the router
func getRouter() *gin.Engine {

	// the openapi generated router uses the defaults, which we want to override to improve and configure logging
	writer := logging.GetGinInternalWriter()
	gin.DefaultWriter = writer
	gin.DefaultErrorWriter = writer
	router := gin.New()

	router.Use(logging.GinHandlerFunc(), gin.Recovery())

	for _, route := range api.NewRouter().Routes() {
		router.Handle(route.Method, route.Path, route.HandlerFunc)
	}

	return router
}

// allow override of the config-file on init. Everything else happens on main to improve testability
func init() {

	configFileEnv := os.Getenv("CONFIG_FILE")
	if configFileEnv != "" {
		configFile = configFileEnv
	}
	logging.Log().Infof("Will read config from %s", configFile)
}

// wildcardOrigin is the CORS origin value that permits requests from any origin.
const wildcardOrigin = "*"

// ResolveAllowedOrigins aggregates the AllowedOrigins from all configured
// services into a deduplicated list of CORS origins. The rules are:
//
//   - If no services are provided, or none of them specify any AllowedOrigins,
//     the function returns ["*"] (wildcard) for backward compatibility.
//   - If any service includes "*" in its AllowedOrigins, the function returns
//     ["*"] because the wildcard takes precedence over specific origins.
//   - Otherwise the function returns the deduplicated union of all origins.
func ResolveAllowedOrigins(services []configModel.ConfiguredService) []string {
	seen := make(map[string]struct{})
	var origins []string

	for _, svc := range services {
		for _, origin := range svc.AllowedOrigins {
			if origin == wildcardOrigin {
				// Wildcard takes precedence — no need to collect further.
				return []string{wildcardOrigin}
			}
			if _, exists := seen[origin]; !exists {
				seen[origin] = struct{}{}
				origins = append(origins, origin)
			}
		}
	}

	// No origins configured at all — default to wildcard for backward compatibility.
	if len(origins) == 0 {
		return []string{wildcardOrigin}
	}

	return origins
}
