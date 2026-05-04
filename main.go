package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fiware/VCVerifier/ccsapi"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
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

// main is the startup method that configures and runs the verifier HTTP server.
// When the config server is enabled, it also starts a second HTTP server for the
// Credentials Config Service (CCS) REST API on a separate port.
func main() {

	configuration, err := configModel.ReadConfig(configFile)
	if err != nil {
		panic(err)
	}

	logging.Configure(configuration.Logging)

	logger := logging.Log()

	logger.Infof("Configuration is: %s", logging.PrettyPrintObject(configuration))

	// --- Optional: Database and Config Server initialization ---
	var db *sql.DB
	var configSrv *http.Server
	var repo database.ServiceRepository

	if configuration.ConfigServer.Enabled {
		db, configSrv, repo, err = initConfigServer(&configuration)
		if err != nil {
			logger.Errorf("Failed to initialize config server: %v", err)
			panic(err)
		}
		defer database.Close(db)
	}

	verifier.InitVerifier(&configuration, repo)
	verifier.InitPresentationParser(&configuration, Health())

	// bgCtx is cancelled before graceful shutdown to stop background tasks.
	bgCtx, cancelBg := context.WithCancel(context.Background())

	// Wire up the database-backed refresh token repository when enabled.
	if configuration.Verifier.RefreshToken.Enabled {
		var refreshDB *sql.DB
		if db != nil {
			// Reuse the existing database connection from the config server.
			refreshDB = db
		} else {
			// Open a dedicated connection when there is no config server.
			refreshDB, err = database.NewConnection(configuration.Database)
			if err != nil {
				logger.Errorf("Refresh tokens enabled but database connection failed: %v", err)
				panic(err)
			}
			if err := database.InitSchema(refreshDB, configuration.Database.Type); err != nil {
				logger.Errorf("Failed to initialize database schema for refresh tokens: %v", err)
				panic(err)
			}
			defer database.Close(refreshDB)
		}
		refreshTokenRepo := database.NewRefreshTokenRepository(refreshDB, configuration.Database.Type)
		verifier.SetRefreshTokenRepo(refreshTokenRepo)
		logger.Info("Refresh token support enabled")

		if interval := configuration.Verifier.RefreshToken.CleanupInterval; interval > 0 {
			refreshTokenRepo.SetCleanupInterval(bgCtx, time.Duration(interval)*time.Second)
			logger.Infof("Refresh token cleanup enabled (interval: %d seconds)", interval)
		}
	}

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

	// Start the verifier server in a goroutine so it doesn't block
	go func() {
		logging.Log().Infof("Starting verifier server on port %v", configuration.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Log().Errorf("Failed to start verifier server: %v", err)
			os.Exit(1)
		}
	}()

	// Start the config server if enabled
	if configSrv != nil {
		go func() {
			logging.Log().Infof("Starting config server on port %v", configuration.ConfigServer.Port)
			if err := configSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Log().Errorf("Failed to start config server: %v", err)
				os.Exit(1)
			}
		}()
	}

	// --- Graceful Shutdown Logic ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	cancelBg()
	logging.Log().Info("Shutting down servers...")

	shutdownTimeout := time.Duration(configuration.Server.ShutdownTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Shut down the config server first (if running)
	if configSrv != nil {
		logging.Log().Info("Shutting down config server...")
		if err := configSrv.Shutdown(ctx); err != nil {
			logging.Log().Errorf("Config server forced to shutdown: %v", err)
		}
		logging.Log().Info("Config server stopped")
	}

	// Shut down the verifier server
	if err := srv.Shutdown(ctx); err != nil {
		logging.Log().Errorf("Verifier server forced to shutdown: %v", err)
	}

	logging.Log().Info("All servers exiting gracefully")
}

// initConfigServer opens a database connection, initializes the schema, creates
// a service repository, and builds the CCS API HTTP server. Returns the database
// connection (for deferred close), the config HTTP server (to be started by the
// caller), the service repository (for verifier integration), or an error if
// setup fails.
func initConfigServer(configuration *configModel.Configuration) (*sql.DB, *http.Server, database.ServiceRepository, error) {
	logger := logging.Log()

	logger.Info("Initializing database connection for config server...")
	db, err := database.NewConnection(configuration.Database)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	logger.Info("Initializing database schema...")
	if err := database.InitSchema(db, configuration.Database.Type); err != nil {
		database.Close(db)
		return nil, nil, nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	repo := database.NewServiceRepository(db, configuration.Database.Type)

	configRouter := getConfigRouter(db, repo)

	cfgSrv := configuration.ConfigServer
	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%v", cfgSrv.Port),
		Handler:      configRouter,
		ReadTimeout:  time.Duration(cfgSrv.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfgSrv.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfgSrv.IdleTimeout) * time.Second,
	}

	logger.Infof("Config server configured on port %v", cfgSrv.Port)
	return db, srv, repo, nil
}

// getConfigRouter creates a Gin router for the CCS API with health check,
// CORS middleware, and all CCS service routes registered.
func getConfigRouter(db *sql.DB, repo database.ServiceRepository) *gin.Engine {
	writer := logging.GetGinInternalWriter()
	gin.DefaultWriter = writer
	gin.DefaultErrorWriter = writer

	router := gin.New()
	router.Use(logging.GinHandlerFunc(), gin.Recovery())

	// CORS - allow all origins for API compatibility; must be registered before routes
	router.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:    []string{"Origin", "Content-Type", "Authorization"},
	}))

	// Health check with database ping
	configHealth := NewConfigServerHealth(db)
	router.GET("/health", ConfigServerHealthReq(configHealth))

	// Register CCS API routes
	ccsapi.RegisterRoutes(router, repo)

	return router
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
