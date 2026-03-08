package anyconnect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
)

// samlResult contains the result of a SAML authentication flow.
type samlResult struct {
	Cookie string
	Err    error
}

// handleSAMLAuth performs browser-based SAML authentication.
// It starts a local HTTP server, opens the SAML URL in the system browser,
// and waits for the IdP to redirect back with the session token.
func handleSAMLAuth(ctx context.Context, samlURL string, timeout time.Duration) (*sessionInfo, error) {
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	// Start local listener on random port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start SAML callback listener: %w", err)
	}
	defer listener.Close()

	callbackPort := listener.Addr().(*net.TCPAddr).Port
	core.Log.Infof("AnyConnect", "SAML callback listener on port %d", callbackPort)

	resultCh := make(chan samlResult, 1)
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Look for session token in query params or form data.
		r.ParseForm()

		cookie := ""
		// Check common SAML callback parameters.
		for _, key := range []string{"webvpn", "token", "session_token", "SAMLResponse"} {
			if v := r.FormValue(key); v != "" {
				cookie = v
				break
			}
		}

		// Also check cookies sent by the redirect.
		for _, c := range r.Cookies() {
			if c.Name == "webvpn" && cookie == "" {
				cookie = c.Value
			}
		}

		if cookie != "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h2>Authentication successful</h2><p>You can close this window.</p><script>window.close()</script></body></html>`)
			once.Do(func() {
				resultCh <- samlResult{Cookie: cookie}
			})
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<html><body><h2>Missing session token</h2></body></html>`)
		}
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	// Build SAML URL with callback.
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/", callbackPort)
	fullURL := samlURL
	if !strings.Contains(fullURL, "?") {
		fullURL += "?"
	} else {
		fullURL += "&"
	}
	fullURL += "callback=" + callbackURL

	// Open browser.
	core.Log.Infof("AnyConnect", "Opening SAML URL in browser: %s", samlURL)
	if err := openBrowser(fullURL); err != nil {
		core.Log.Warnf("AnyConnect", "Failed to open browser: %v", err)
		return nil, fmt.Errorf("open browser for SAML: %w (URL: %s)", err, fullURL)
	}

	// Wait for callback or timeout.
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case result := <-resultCh:
		if result.Err != nil {
			return nil, result.Err
		}
		core.Log.Infof("AnyConnect", "SAML authentication completed")
		return &sessionInfo{Cookie: result.Cookie}, nil
	case <-timeoutCtx.Done():
		return nil, fmt.Errorf("SAML authentication timed out after %s", timeout)
	}
}

// openBrowser opens a URL in the system default browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
