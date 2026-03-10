// Package helpers provides test infrastructure for black-box integration testing of VCVerifier.
package helpers

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	// HealthPollInterval is the interval between health check polls when waiting for the verifier to start.
	HealthPollInterval = 100 * time.Millisecond
	// HealthPollTimeout is the maximum time to wait for the verifier to become healthy.
	HealthPollTimeout = 15 * time.Second
	// ShutdownGracePeriod is the time to wait after SIGTERM before sending SIGKILL.
	ShutdownGracePeriod = 5 * time.Second
)

// VerifierProcess represents a running VCVerifier binary managed by the test harness.
type VerifierProcess struct {
	cmd       *exec.Cmd
	Port      int
	BaseURL   string
	configDir string
}

// BuildVerifier compiles the VCVerifier binary and places it in a temporary directory.
// projectRoot must point to the root of the VCVerifier source tree.
func BuildVerifier(projectRoot string) (binaryPath string, err error) {
	tmpDir, err := os.MkdirTemp("", "vcverifier-it-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir for binary: %w", err)
	}

	binaryPath = filepath.Join(tmpDir, "vcverifier")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("building verifier binary: %w", err)
	}

	return binaryPath, nil
}

// StartVerifier launches a VCVerifier process with the given YAML config and waits until it is healthy.
// projectRoot is needed so the binary can find view templates via relative paths.
// Optional extraEnv entries are added to the process environment (e.g., "SSL_CERT_FILE=/path/to/ca.pem").
func StartVerifier(configYAML string, projectRoot string, binaryPath string, extraEnv ...string) (*VerifierProcess, error) {
	configDir, err := os.MkdirTemp("", "vcverifier-config-*")
	if err != nil {
		return nil, fmt.Errorf("creating config temp dir: %w", err)
	}

	configPath := filepath.Join(configDir, "server.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		os.RemoveAll(configDir)
		return nil, fmt.Errorf("writing config file: %w", err)
	}

	// Parse the port from the config to know where to poll health.
	port, err := extractPortFromConfig(configYAML)
	if err != nil {
		os.RemoveAll(configDir)
		return nil, fmt.Errorf("extracting port from config: %w", err)
	}

	cmd := exec.Command(binaryPath)
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		"CONFIG_FILE="+configPath,
		"GIN_MODE=release",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		os.RemoveAll(configDir)
		return nil, fmt.Errorf("starting verifier process: %w", err)
	}

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	vp := &VerifierProcess{
		cmd:       cmd,
		Port:      port,
		BaseURL:   baseURL,
		configDir: configDir,
	}

	if err := waitForHealthy(baseURL, HealthPollTimeout, cmd); err != nil {
		vp.Stop()
		return nil, fmt.Errorf("verifier did not become healthy: %w", err)
	}

	return vp, nil
}

// Stop gracefully shuts down the verifier process and cleans up temporary files.
func (vp *VerifierProcess) Stop() {
	if vp.cmd != nil && vp.cmd.Process != nil {
		_ = vp.cmd.Process.Signal(syscall.SIGTERM)

		done := make(chan error, 1)
		go func() {
			done <- vp.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited gracefully.
		case <-time.After(ShutdownGracePeriod):
			_ = vp.cmd.Process.Kill()
			<-done
		}
	}

	if vp.configDir != "" {
		os.RemoveAll(vp.configDir)
	}
}

// waitForHealthy polls the /health endpoint until it returns 200 or the timeout expires.
func waitForHealthy(baseURL string, timeout time.Duration, cmd *exec.Cmd) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	healthURL := baseURL + "/health"

	for time.Now().Before(deadline) {
		// Check if process has already exited.
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return fmt.Errorf("verifier process exited prematurely with code %d", cmd.ProcessState.ExitCode())
		}

		resp, err := client.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		time.Sleep(HealthPollInterval)
	}

	return fmt.Errorf("health check at %s did not return 200 within %v", healthURL, timeout)
}

// GetFreePort returns an available TCP port by binding to :0 and reading the assigned port.
func GetFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("binding to free port: %w", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// extractPortFromConfig parses the port value from a YAML config string.
// This is a simple extraction to avoid pulling in a YAML library.
func extractPortFromConfig(yaml string) (int, error) {
	var port int
	_, err := fmt.Sscanf(findYAMLValue(yaml, "port"), "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("parsing port from config: %w", err)
	}
	return port, nil
}

// findYAMLValue does a simple line-by-line scan for "key: value" and returns the value.
func findYAMLValue(yaml string, key string) string {
	lines := splitLines(yaml)
	target := key + ":"
	for _, line := range lines {
		trimmed := trimSpace(line)
		if len(trimmed) > len(target) && trimmed[:len(target)] == target {
			return trimSpace(trimmed[len(target):])
		}
	}
	return ""
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
