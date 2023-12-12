/*
 * vcverifier
 *
 * Backend component to verify credentials
 *
 * API version: 0.0.1
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package openapi

import (
	"net/http"
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/fiware/VCVerifier/verifier"

	"github.com/gin-gonic/gin"
)

var frontendVerifier verifier.Verifier

func getFrontendVerifier() verifier.Verifier {
	if frontendVerifier == nil {
		frontendVerifier = verifier.GetVerifier()
	}
	return frontendVerifier
}

// VerifierPageDisplayQRSIOP - Presents a qr as starting point for the auth process
func VerifierPageDisplayQRSIOP(c *gin.Context) {

	state, stateExists := c.GetQuery("state")
	if !stateExists {
		c.AbortWithStatusJSON(400, ErrorMessageNoState)
		// early exit
		return
	}

	callback, callbackExists := c.GetQuery("client_callback")
	if !callbackExists {
		c.AbortWithStatusJSON(400, ErrorMessageNoCallback)
		// early exit
		return
	}

	clientId, clientIdExists := c.GetQuery("client_id")
	if !clientIdExists {
		logging.Log().Infof("Start a login flow for a not specified client.")
	}

	qr, err := getFrontendVerifier().ReturnLoginQR(c.Request.Host, "https", callback, state, clientId)
	if err != nil {
		c.AbortWithStatusJSON(500, ErrorMessage{"qr_generation_error", err.Error()})
		return
	}

	c.HTML(http.StatusOK, buildPath(configuration.TemplateDir, "verifier_present_qr.html"), gin.H{"qrcode": qr})
}

func buildPath(templateDir string, file string) string {
	if strings.HasSuffix(templateDir, "/") {
		return templateDir + file
	} else {
		return templateDir + "/" + file
	}
}

// VerifierPageLoginExpired - Presents a page when the login session is expired
func VerifierPageLoginExpired(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}
