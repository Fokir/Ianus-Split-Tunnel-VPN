//go:build windows

package anyconnect

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"awg-split-tunnel/internal/core"
)

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

const (
	userAgent   = "AnyConnect Windows 4.10.07061"
	agentVer    = "4.10.07061"
	deviceType  = "win"
	platformVer = "10.0.19045"
)

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
func authenticate(br *bufio.Reader, conn io.Writer, host string, creds credentials) (*sessionInfo, error) {
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
			`<device-id device-type="%s" platform-version="%s">win</device-id>`+
			`%s%s`+
			`</config-auth>`,
		agentVer, deviceType, platformVer, groupAccessXML, groupSelectXML)

	result, err := doAuthPost(br, conn, host, "/", initXML, nil)
	if err != nil {
		return nil, fmt.Errorf("init request: %w", err)
	}
	resp := result.config
	cookies := result.cookies

	// Log form fields from the server for debugging.
	if resp.Auth != nil && resp.Auth.Form != nil {
		for _, inp := range resp.Auth.Form.Inputs {
			core.Log.Debugf("AnyConnect", "Init form field: name=%q type=%q label=%q value=%q",
				inp.Name, inp.Type, inp.Label, inp.Value)
		}
	}
	if resp.Auth != nil && resp.Auth.Message != "" {
		core.Log.Debugf("AnyConnect", "Init message: %s", resp.Auth.Message)
	}
	if len(cookies) > 0 {
		var names []string
		for _, c := range cookies {
			names = append(names, c.Name)
		}
		core.Log.Debugf("AnyConnect", "Cookies from server: %v", names)
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
	authXML := buildFormReply(resp, creds, opaque, host)
	core.Log.Debugf("AnyConnect", "Auth reply XML: %s", authXML)
	result, err = doAuthPost(br, conn, host, action, authXML, cookies)
	if err != nil {
		return nil, fmt.Errorf("auth request: %w", err)
	}
	resp = result.config
	cookies = result.cookies

	// Multi-round: server may ask for more credentials (e.g. 2FA in a separate round).
	const maxRounds = 5
	for round := 0; round < maxRounds; round++ {
		if resp.Type != "auth-request" {
			break
		}
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

		authXML = buildFormReply(resp, creds, opaque, host)
		result, err = doAuthPost(br, conn, host, action, authXML, cookies)
		if err != nil {
			return nil, fmt.Errorf("auth round %d: %w", round+2, err)
		}
		resp = result.config
		cookies = result.cookies
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
func buildFormReply(resp *configAuth, creds credentials, opaque, host string) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">`)
	sb.WriteString(fmt.Sprintf(`<version who="vpn">%s</version>`, agentVer))
	sb.WriteString(fmt.Sprintf(`<device-id device-type="%s" platform-version="%s">win</device-id>`, deviceType, platformVer))

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

func doAuthPost(br *bufio.Reader, conn io.Writer, host, path, body string, cookies []*http.Cookie) (*authPostResult, error) {
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
		path, host, userAgent, deviceType, cookieHeader, len(body), body)

	if _, err := io.WriteString(conn, reqStr); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	core.Log.Debugf("AnyConnect", "Response (HTTP %d, %d bytes): %s", resp.StatusCode, len(respBody), string(respBody))

	var ca configAuth
	if err := xml.Unmarshal(respBody, &ca); err != nil {
		return nil, fmt.Errorf("parse XML: %w (body: %s)", err, string(respBody))
	}

	// Merge cookies: keep old, add/update new.
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}
	for _, c := range resp.Cookies() {
		cookieMap[c.Name] = c
	}
	var merged []*http.Cookie
	for _, c := range cookieMap {
		merged = append(merged, c)
	}

	return &authPostResult{config: &ca, cookies: merged}, nil
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}
