package anyconnect

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"awg-split-tunnel/internal/core"
)

// RedirectError is returned when the server redirects to a different host,
// requiring a new TLS connection.
type RedirectError struct {
	Host string // new host (without port)
	Port string // new port (may be empty → default 443)
	Path string // new path
}

func (e *RedirectError) Error() string {
	return fmt.Sprintf("redirect to %s:%s%s", e.Host, e.Port, e.Path)
}

// ---- XML structures for AnyConnect authentication ----

type configAuth struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Auth    *authElement
	Opaque  *opaqueElement `xml:"opaque"`
	Error   string         `xml:"error"`

	// Fields present in "complete" response.
	SessionToken string `xml:"session-token"`
}

type authElement struct {
	XMLName xml.Name `xml:"auth"`
	ID      string   `xml:"id,attr"`
	Title   string   `xml:"title"`
	Message string   `xml:"message"`
	Banner  string   `xml:"banner"`
	Error   string   `xml:"error"`
	Form    *authForm
}

type authForm struct {
	XMLName xml.Name    `xml:"form"`
	Action  string      `xml:"action,attr"`
	Method  string      `xml:"method,attr"`
	Inputs  []formInput `xml:"input"`
}

type formInput struct {
	XMLName xml.Name `xml:"input"`
	Type    string   `xml:"type,attr"`
	Name    string   `xml:"name,attr"`
	Label   string   `xml:"label,attr"`
	Value   string   `xml:"value,attr"`
}

type opaqueElement struct {
	XMLName xml.Name `xml:"opaque"`
	Inner   string   `xml:",innerxml"`
}

// sessionInfo is returned after successful authentication.
type sessionInfo struct {
	Cookie string // webvpn session cookie
}

// Platform-specific constants (userAgent, agentVer, deviceType, platformVer)
// are defined in platform_windows.go and platform_darwin.go.

// credentials holds all available auth values for form filling.
type credentials struct {
	Username string
	Password string
	OTPCode  string
	Group    string
}

// authenticate performs multi-round XML form authentication over an existing
// HTTP connection. It dynamically parses server forms and fills fields.
// Supports single-round (all fields in one form) and multi-round (2FA in
// a separate form) authentication.
func authenticate(br *bufio.Reader, conn io.Writer, host string, creds credentials, cid clientID) (*sessionInfo, error) {
	core.Log.Infof("AnyConnect", "Client identity: UA=%q version=%q device=%q platform=%q",
		cid.UserAgent, cid.Version, cid.DeviceType, cid.PlatformVer)

	// Phase 1: init request.
	// group-access tells Cisco ASA which tunnel group (connection profile) to use.
	// Without it, the server may default to DefaultWEBVPNGroup which might not accept the user.
	groupAccessXML := fmt.Sprintf(`<group-access>https://%s</group-access>`, xmlEscape(host))

	var groupSelectXML string
	if creds.Group != "" {
		groupSelectXML = fmt.Sprintf(`<group-select>%s</group-select>`, xmlEscape(creds.Group))
	}
	initXML := fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?>`+
			`<config-auth client="vpn" type="init" aggregate-auth-version="2">`+
			`<version who="vpn">%s</version>`+
			`<device-id device-type="%s" platform-version="%s">%s</device-id>`+
			`%s%s`+
			`</config-auth>`,
		cid.Version, cid.DeviceType, cid.PlatformVer, cid.DeviceType, groupAccessXML, groupSelectXML)

	core.Log.Infof("AnyConnect", "Init XML: %s", initXML)
	result, err := doAuthPost(br, conn, host, "/", initXML, nil, cid)
	if err != nil {
		return nil, fmt.Errorf("init request: %w", err)
	}
	resp := result.config
	cookies := result.cookies

	// Log init response details.
	core.Log.Infof("AnyConnect", "Init response: type=%q", resp.Type)
	if resp.Auth != nil {
		core.Log.Infof("AnyConnect", "Auth element: id=%q title=%q message=%q error=%q",
			resp.Auth.ID, resp.Auth.Title, resp.Auth.Message, resp.Auth.Error)
		if resp.Auth.Form != nil {
			core.Log.Infof("AnyConnect", "Form: action=%q method=%q fields=%d",
				resp.Auth.Form.Action, resp.Auth.Form.Method, len(resp.Auth.Form.Inputs))
			for _, inp := range resp.Auth.Form.Inputs {
				core.Log.Infof("AnyConnect", "  Field: name=%q type=%q label=%q value=%q",
					inp.Name, inp.Type, inp.Label, inp.Value)
			}
		}
	}
	if resp.Error != "" {
		core.Log.Warnf("AnyConnect", "Init error: %s", resp.Error)
	}
	if len(cookies) > 0 {
		var names []string
		for _, c := range cookies {
			names = append(names, c.Name)
		}
		core.Log.Infof("AnyConnect", "Cookies from server: %v", names)
	}

	action := "/"
	var opaque string
	if resp.Auth != nil && resp.Auth.Form != nil && resp.Auth.Form.Action != "" {
		action = resp.Auth.Form.Action
	}
	if resp.Opaque != nil {
		opaque = resp.Opaque.Inner
	}

	// Phase 2: fill the form the server sent us.
	authXML := buildFormReply(resp, creds, opaque, host, cid)
	core.Log.Infof("AnyConnect", "Auth reply XML (credentials masked): %s", maskCredentials(authXML, creds))
	result, err = doAuthPost(br, conn, host, action, authXML, cookies, cid)
	if err != nil {
		return nil, fmt.Errorf("auth request: %w", err)
	}
	resp = result.config
	cookies = result.cookies
	core.Log.Infof("AnyConnect", "Auth response: type=%q", resp.Type)
	if resp.Auth != nil {
		if resp.Auth.Error != "" {
			core.Log.Warnf("AnyConnect", "Auth response error: %s", resp.Auth.Error)
		}
		if resp.Auth.Message != "" {
			core.Log.Infof("AnyConnect", "Auth response message: %s", resp.Auth.Message)
		}
		if resp.Auth.Banner != "" {
			core.Log.Infof("AnyConnect", "Auth response banner: %s", resp.Auth.Banner)
		}
		if resp.Auth.Form != nil {
			core.Log.Infof("AnyConnect", "Auth response has form: action=%q fields=%d",
				resp.Auth.Form.Action, len(resp.Auth.Form.Inputs))
			for _, inp := range resp.Auth.Form.Inputs {
				core.Log.Infof("AnyConnect", "  Field: name=%q type=%q label=%q", inp.Name, inp.Type, inp.Label)
			}
		}
	}
	if resp.Error != "" {
		core.Log.Warnf("AnyConnect", "Auth response top-level error: %s", resp.Error)
	}

	// Multi-round: server may ask for more credentials (e.g. 2FA in a separate round).
	const maxRounds = 5
	for round := 0; round < maxRounds; round++ {
		if resp.Type != "auth-request" {
			break
		}
		core.Log.Infof("AnyConnect", "Multi-round auth: round %d, type=%q", round+2, resp.Type)
		if resp.Auth != nil && resp.Auth.Error != "" {
			return nil, fmt.Errorf("auth error: %s", resp.Auth.Error)
		}
		if resp.Error != "" {
			return nil, fmt.Errorf("auth error: %s", resp.Error)
		}

		// Update opaque and action from new response.
		if resp.Opaque != nil {
			opaque = resp.Opaque.Inner
		}
		if resp.Auth != nil && resp.Auth.Form != nil && resp.Auth.Form.Action != "" {
			action = resp.Auth.Form.Action
		}

		if resp.Auth != nil && resp.Auth.Form != nil {
			for _, inp := range resp.Auth.Form.Inputs {
				core.Log.Infof("AnyConnect", "  Round %d field: name=%q type=%q label=%q", round+2, inp.Name, inp.Type, inp.Label)
			}
		}

		authXML = buildFormReply(resp, creds, opaque, host, cid)
		core.Log.Infof("AnyConnect", "Round %d reply (masked): %s", round+2, maskCredentials(authXML, creds))
		result, err = doAuthPost(br, conn, host, action, authXML, cookies, cid)
		if err != nil {
			return nil, fmt.Errorf("auth round %d: %w", round+2, err)
		}
		resp = result.config
		cookies = result.cookies
		core.Log.Infof("AnyConnect", "Round %d response: type=%q", round+2, resp.Type)
	}

	// Check for errors.
	if resp.Auth != nil && resp.Auth.Error != "" {
		return nil, fmt.Errorf("auth error: %s", resp.Auth.Error)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("auth error: %s", resp.Error)
	}

	if resp.Type != "complete" {
		return nil, fmt.Errorf("unexpected auth response type: %s", resp.Type)
	}

	if resp.SessionToken == "" {
		return nil, fmt.Errorf("no session token in auth response")
	}

	return &sessionInfo{
		Cookie: resp.SessionToken,
	}, nil
}

// buildFormReply inspects the server's form fields and fills them from creds.
// It handles any combination: username+password, username+password+otp,
// otp-only (second round), etc.
func buildFormReply(resp *configAuth, creds credentials, opaque, host string, cid clientID) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">`)
	sb.WriteString(fmt.Sprintf(`<version who="vpn">%s</version>`, cid.Version))
	sb.WriteString(fmt.Sprintf(`<device-id device-type="%s" platform-version="%s">%s</device-id>`, cid.DeviceType, cid.PlatformVer, cid.DeviceType))

	if opaque != "" {
		sb.WriteString(`<opaque is-for="sg">`)
		sb.WriteString(opaque)
		sb.WriteString(`</opaque>`)
	}

	// Echo back the auth id from the server (e.g., <auth id="main">).
	if resp.Auth != nil && resp.Auth.ID != "" {
		sb.WriteString(fmt.Sprintf(`<auth id="%s">`, xmlEscape(resp.Auth.ID)))
	} else {
		sb.WriteString(`<auth>`)
	}

	// Parse form fields and fill them dynamically.
	// Use the field's name attribute as the XML element name (e.g., <secondary_password>).
	// This correctly handles multi-password forms (password + secondary_password for OTP).
	if resp.Auth != nil && resp.Auth.Form != nil {
		for _, input := range resp.Auth.Form.Inputs {
			val := matchFieldValue(input, creds)
			elemName := input.Name
			if elemName == "" {
				if input.Type == "text" {
					elemName = "username"
				} else {
					elemName = "password"
				}
			}
			sb.WriteString(fmt.Sprintf(`<%s>%s</%s>`, elemName, xmlEscape(val), elemName))
		}
	} else {
		// Fallback: no form info, send username + password.
		sb.WriteString(fmt.Sprintf(`<username>%s</username>`, xmlEscape(creds.Username)))
		sb.WriteString(fmt.Sprintf(`<password>%s</password>`, xmlEscape(creds.Password)))
	}

	sb.WriteString(`</auth>`)

	// Include group-access (required by Cisco ASA for tunnel group selection).
	if host != "" {
		sb.WriteString(fmt.Sprintf(`<group-access>https://%s</group-access>`, xmlEscape(host)))
	}
	if creds.Group != "" {
		sb.WriteString(fmt.Sprintf(`<group-select>%s</group-select>`, xmlEscape(creds.Group)))
	}

	sb.WriteString(`</config-auth>`)
	return sb.String()
}

// matchFieldValue determines which credential value to put into a form field
// based on the field's name, label, and type.
func matchFieldValue(input formInput, creds credentials) string {
	name := strings.ToLower(input.Name)
	label := strings.ToLower(input.Label)

	// Username field.
	if name == "username" || name == "user" || name == "login" {
		return creds.Username
	}

	// OTP / 2FA / secondary password field.
	if isOTPField(name, label) {
		if creds.OTPCode != "" {
			return creds.OTPCode
		}
		// Fallback: some servers put OTP in "secondary_password".
		return ""
	}

	// Password field (primary).
	if input.Type == "password" || name == "password" || name == "passwd" {
		return creds.Password
	}

	// Text fields default to username.
	if input.Type == "text" {
		return creds.Username
	}

	return ""
}

// isOTPField checks if a form field is for a one-time code based on common
// naming patterns used by Cisco ASA, ocserv, and AnyLink.
func isOTPField(name, label string) bool {
	otpNames := []string{
		"secondary_password", "secondpassword", "second_password",
		"otp", "totp", "token", "passcode", "verification",
		"challenge", "answer", "pin",
	}
	for _, n := range otpNames {
		if strings.Contains(name, n) {
			return true
		}
	}

	otpLabels := []string{
		"verification code", "second password", "token",
		"otp", "totp", "passcode", "two-factor", "2fa",
		"challenge", "security code", "one-time",
	}
	for _, l := range otpLabels {
		if strings.Contains(label, l) {
			return true
		}
	}
	return false
}

// authPostResult contains the parsed XML response and any cookies set by the server.
type authPostResult struct {
	config  *configAuth
	cookies []*http.Cookie
}

const maxRedirects = 10

func doAuthPost(br *bufio.Reader, conn io.Writer, host, path, body string, cookies []*http.Cookie, cid clientID) (*authPostResult, error) {
	for redirects := 0; ; redirects++ {
		if redirects >= maxRedirects {
			return nil, fmt.Errorf("too many redirects")
		}

		var cookieHeader string
		if len(cookies) > 0 {
			var parts []string
			for _, c := range cookies {
				parts = append(parts, c.Name+"="+c.Value)
			}
			cookieHeader = "Cookie: " + strings.Join(parts, "; ") + "\r\n"
		}

		reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Content-Type: application/xml; charset=utf-8\r\n"+
			"Accept: */*\r\n"+
			"Accept-Encoding: identity\r\n"+
			"X-Transcend-Version: 1\r\n"+
			"X-Aggregate-Auth: 1\r\n"+
			"X-AnyConnect-Platform: %s\r\n"+
			"%s"+
			"Content-Length: %d\r\n"+
			"\r\n%s",
			path, host, cid.UserAgent, cid.DeviceType, cookieHeader, len(body), body)

		core.Log.Infof("AnyConnect", "POST %s (host=%s, body=%d bytes)", path, host, len(body))

		if _, err := io.WriteString(conn, reqStr); err != nil {
			return nil, fmt.Errorf("write request: %w", err)
		}

		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}

		core.Log.Infof("AnyConnect", "Response: HTTP %d, Content-Type=%q",
			resp.StatusCode, resp.Header.Get("Content-Type"))

		// Handle redirects (301, 302, 303, 307, 308).
		if isRedirect(resp.StatusCode) {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// Merge cookies from redirect response.
			for _, c := range resp.Cookies() {
				cookies = mergeCookie(cookies, c)
			}

			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, fmt.Errorf("HTTP %d without Location header", resp.StatusCode)
			}
			core.Log.Infof("AnyConnect", "Redirect %d → %s", resp.StatusCode, loc)

			newHost, newPort, newPath, err := parseRedirectLocation(loc, host)
			if err != nil {
				return nil, fmt.Errorf("parse redirect location %q: %w", loc, err)
			}

			// Same host — follow on the same TLS connection.
			if newHost == host {
				path = newPath
				continue
			}

			// Different host — need a new TLS connection; bubble up.
			return nil, &RedirectError{Host: newHost, Port: newPort, Path: newPath}
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			errBody, _ := io.ReadAll(resp.Body)
			core.Log.Warnf("AnyConnect", "HTTP %d error, body (%d bytes): %s",
				resp.StatusCode, len(errBody), string(errBody))
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}

		core.Log.Infof("AnyConnect", "Response body (%d bytes): %s", len(respBody), string(respBody))

		var ca configAuth
		if err := xml.Unmarshal(respBody, &ca); err != nil {
			return nil, fmt.Errorf("parse XML: %w (body: %s)", err, string(respBody))
		}

		// Merge cookies: keep old, add/update new.
		for _, c := range resp.Cookies() {
			cookies = mergeCookie(cookies, c)
		}

		return &authPostResult{config: &ca, cookies: cookies}, nil
	}
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// parseRedirectLocation extracts host, port, and path from a Location header.
// Handles both absolute URLs and relative paths.
func parseRedirectLocation(loc, currentHost string) (host, port, path string, err error) {
	if strings.HasPrefix(loc, "/") {
		// Relative path — same host.
		return currentHost, "", loc, nil
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "", "", "", err
	}
	host = u.Hostname()
	port = u.Port()
	path = u.RequestURI()
	if path == "" {
		path = "/"
	}
	if host == "" {
		host = currentHost
	}
	return host, port, path, nil
}

func mergeCookie(cookies []*http.Cookie, c *http.Cookie) []*http.Cookie {
	for i, existing := range cookies {
		if existing.Name == c.Name {
			cookies[i] = c
			return cookies
		}
	}
	return append(cookies, c)
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}

// maskCredentials replaces sensitive values in XML with "***" for safe logging.
func maskCredentials(xmlStr string, creds credentials) string {
	masked := xmlStr
	if creds.Password != "" {
		masked = strings.ReplaceAll(masked, xmlEscape(creds.Password), "***")
	}
	if creds.OTPCode != "" {
		masked = strings.ReplaceAll(masked, xmlEscape(creds.OTPCode), "***")
	}
	return masked
}
