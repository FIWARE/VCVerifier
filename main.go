package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

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

	logging.Configure(
		configuration.Logging.JsonLogging,
		configuration.Logging.Level,
		configuration.Logging.LogRequests,
		configuration.Logging.PathsToSkip)

	logger := logging.Log()

	logger.Infof("Configuration is: %s", logging.PrettyPrintObject(configuration))

	verifier.InitVerifier(&configuration)
	verifier.InitPresentationParser(&configuration, Health())

	router := getRouter()

	// health check
	router.GET("/health", HealthReq)

	router.Use(cors.New(cors.Config{
		// we need to allow all, since we do not know the potential origin of a wallet
		AllowOrigins:     []string{"*"},
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

	router.Run(fmt.Sprintf("0.0.0.0:%v", configuration.Server.Port))

	logger.Infof("Started router at %v", configuration.Server.Port)
}

// initiate the router
func getRouter() *gin.Engine {
	// the openapi generated router uses the defaults, which we want to override to improve and configure logging
	router := gin.New()
	router.Use(logging.GinHandlerFunc(), gin.Recovery())

	for _, route := range api.NewRouter().Routes() {

		switch route.Method {
		case http.MethodGet:
			router.GET(route.Path, route.HandlerFunc)
		case http.MethodPost:
			router.POST(route.Path, route.HandlerFunc)
		case http.MethodPut:
			router.PUT(route.Path, route.HandlerFunc)
		case http.MethodPatch:
			router.PATCH(route.Path, route.HandlerFunc)
		case http.MethodDelete:
			router.DELETE(route.Path, route.HandlerFunc)
		}
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
