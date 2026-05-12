package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hellofresh/health-go/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHealthReq_ReturnsOK(t *testing.T) {
	router := gin.New()
	router.GET("/health", HealthReq)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result health.Check
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, health.StatusOK, result.Status)
}

func TestHealth_ReturnsSingleton(t *testing.T) {
	h := Health()
	assert.NotNil(t, h)
	// Should be the same singleton on multiple calls
	assert.Equal(t, h, Health())
}

func TestNewConfigServerHealth_WithValidDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	h := NewConfigServerHealth(db)
	assert.NotNil(t, h)

	// Measure health — should be OK with a live SQLite connection
	result := h.Measure(t.Context())
	assert.Equal(t, health.StatusOK, result.Status)
}

func TestNewConfigServerHealth_WithClosedDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	_ = db.Close() // Close immediately to simulate a dead connection

	h := NewConfigServerHealth(db)
	assert.NotNil(t, h)

	// Measure health — should be unhealthy with a closed connection
	result := h.Measure(t.Context())
	assert.Equal(t, health.StatusUnavailable, result.Status)
}

func TestConfigServerHealthReq_ReturnsOKWithLiveDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	h := NewConfigServerHealth(db)

	router := gin.New()
	router.GET("/health", ConfigServerHealthReq(h))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result health.Check
	err = json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, health.StatusOK, result.Status)
}

func TestConfigServerHealthReq_ReturnsUnavailableWithClosedDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	_ = db.Close()

	h := NewConfigServerHealth(db)

	router := gin.New()
	router.GET("/health", ConfigServerHealthReq(h))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var result health.Check
	err = json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, health.StatusUnavailable, result.Status)
}
