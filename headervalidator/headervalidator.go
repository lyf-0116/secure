// Package headervalidator contains syntax-aware validators for security
// header values. Each header family gets its own validation domain because
// CSP sources, Permissions-Policy allowlists, and simple token headers do not
// share one grammar.
package headervalidator

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Type identifies a validation domain. The string value is the canonical HTTP
// header name when the domain corresponds to exactly one header.
type Type string

const (
	// ContentSecurityPolicy is the CSP header validation domain.
	ContentSecurityPolicy Type = "Content-Security-Policy"
	// ContentSecurityPolicyReportOnly is the report-only CSP domain.
	ContentSecurityPolicyReportOnly Type = "Content-Security-Policy-Report-Only"
	// PermissionsPolicy is the modern Permissions-Policy validation domain.
	PermissionsPolicy Type = "Permissions-Policy"
	// FeaturePolicy is the deprecated Feature-Policy validation domain.
	FeaturePolicy Type = "Feature-Policy"
	// FrameOptions is the X-Frame-Options validation domain.
	FrameOptions Type = "X-Frame-Options"
	// ContentTypeOptions is the X-Content-Type-Options validation domain.
	ContentTypeOptions Type = "X-Content-Type-Options"
	// XSSProtection is the legacy X-XSS-Protection validation domain.
	XSSProtection Type = "X-XSS-Protection"
)

var (
	headerNamePattern    = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)
	cspDirectivePattern  = regexp.MustCompile(`^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$`)
	featureNamePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*$`)
	cspQuotedWordPattern = regexp.MustCompile(`^'[A-Za-z][A-Za-z0-9-]*'$`)
	cspNoncePattern      = regexp.MustCompile(`^'nonce-[A-Za-z0-9+/_-]+={0,2}'$`)
	cspHashPattern       = regexp.MustCompile(`^'(sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'$`)
	schemePattern        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:$`)
)

// knownCSPDirectives is intentionally exhaustive over stable, deprecated, and
// experimental directives seen in configuration. Unknown directive names are
// rejected because they are usually typos or header-injection residue.
var knownCSPDirectives = map[string]struct{}{
	// Fetch directives.
	"child-src": {}, "connect-src": {}, "default-src": {}, "font-src": {},
	"frame-src": {}, "img-src": {}, "manifest-src": {}, "media-src": {},
	"object-src": {}, "prefetch-src": {}, "script-src": {},
	"script-src-attr": {}, "script-src-elem": {}, "style-src": {},
	"style-src-attr": {}, "style-src-elem": {}, "worker-src": {},
	"fenced-frame-src": {}, "webrtc-src": {},

	// Document directives.
	"base-uri": {}, "sandbox": {},

	// Navigation directives.
	"form-action": {}, "frame-ancestors": {}, "navigate-to": {},

	// Reporting directives.
	"report-uri": {}, "report-to": {},

	// Other directives.
	"require-trusted-types-for": {}, "trusted-types": {},
	"upgrade-insecure-requests": {},

	// Deprecated but still present in existing policies.
	"block-all-mixed-content": {}, "plugin-types": {}, "referrer": {},
	"require-sri-for": {}, "disown-opener": {},
}

// Validate checks a value using the domain selected by headerName. Unknown
// headers receive generic header-value safety checks only.
func Validate(headerName, value string) error {
	headerName = strings.TrimSpace(headerName)
	if headerName == "" {
		return fmt.Errorf("header name is required")
	}
	if !headerNamePattern.MatchString(headerName) {
		return fmt.Errorf("invalid header name %q", headerName)
	}

	headerType := Type(strings.TrimSpace(headerName))
	switch Type(strings.ToLower(string(headerType))) {
	case Type(strings.ToLower(string(ContentSecurityPolicy))):
		return ValidateCSP(value)
	case Type(strings.ToLower(string(ContentSecurityPolicyReportOnly))):
		return ValidateCSP(value)
	case Type(strings.ToLower(string(PermissionsPolicy))):
		return ValidatePermissionsPolicy(value)
	case Type(strings.ToLower(string(FrameOptions))):
		return ValidateFrameOptions(value)
	case Type(strings.ToLower(string(ContentTypeOptions))):
		return ValidateContentTypeOptions(value)
	case Type(strings.ToLower(string(FeaturePolicy))):
		return ValidateFeaturePolicy(value)
	case Type(strings.ToLower(string(XSSProtection))):
		return ValidateXSSProtection(value)
	default:
		return validateHeaderChars(value)
	}
}

// ValidateType checks a value in an explicit validation domain.
func ValidateType(headerType Type, value string) error {
	return Validate(string(headerType), value)
}

// ValidateCSP validates a raw Content-Security-Policy value. The dynamic
// $NONCE placeholder is accepted here and checked again after substitution.
func ValidateCSP(policy string) error {
	if strings.TrimSpace(policy) == "" {
		return fmt.Errorf("content security policy is empty")
	}
	if err := validateHeaderChars(policy); err != nil {
		return fmt.Errorf("invalid content security policy: %w", err)
	}

	// New uses this validator before generating a request nonce. Replace the
	// placeholder with a syntactically valid nonce so startup validation sees
	// the same shape that will be written.
	normalized := strings.ReplaceAll(policy, "$NONCE", "'nonce-aaaaaaaaaaaaaaaaaaaaaa'")
	seen := make(map[string]struct{})
	directiveCount := 0

	segments := strings.Split(normalized, ";")
	for segmentIndex, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			// A trailing semicolon is tolerated for handwritten policies; an
			// empty middle segment is not.
			if segmentIndex < len(segments)-1 && strings.TrimSpace(segments[segmentIndex+1]) != "" {
				return fmt.Errorf("content security policy contains an empty directive")
			}
			continue
		}

		fields := strings.Fields(segment)
		directive := fields[0]
		if err := ValidateCSPDirectiveName(directive); err != nil {
			return err
		}
		directiveKey := strings.ToLower(directive)
		if _, duplicate := seen[directiveKey]; duplicate {
			return fmt.Errorf("duplicate CSP directive %q", directive)
		}
		seen[directiveKey] = struct{}{}
		directiveCount++

		for _, token := range fields[1:] {
			if err := validateCSPToken(directive, token); err != nil {
				return err
			}
		}
	}

	if directiveCount == 0 {
		return fmt.Errorf("content security policy contains no directives")
	}

	return nil
}

// ValidateCSPDirectiveName reports whether name is a known CSP directive.
func ValidateCSPDirectiveName(name string) error {
	name = strings.TrimSpace(name)
	if !cspDirectivePattern.MatchString(name) {
		return fmt.Errorf("invalid CSP directive name %q", name)
	}
	if _, allowed := knownCSPDirectives[strings.ToLower(name)]; !allowed {
		return fmt.Errorf("unknown CSP directive %q", name)
	}
	return nil
}

// ValidateCSPToken validates one value token for a CSP directive.
func ValidateCSPToken(directive, token string) error {
	return validateCSPToken(directive, token)
}

// ValidateValueCharset rejects control characters and characters commonly used
// to break out of a header directive or value token.
func ValidateValueCharset(directive, value string) error {
	if value == "" {
		return fmt.Errorf("empty value for CSP directive %s", directive)
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char < 0x20 || char > 0x7e {
			return fmt.Errorf("unallowed value %q for directive %s", value, directive)
		}
		switch char {
		case ';', '\\', '"', '<', '>', '`', '|', '^', '{', '}':
			return fmt.Errorf("unallowed value %q for directive %s", value, directive)
		}
	}
	return nil
}

// ValidateCSPValue is an alias for ValidateCSPToken.
func ValidateCSPValue(directive, token string) error {
	return ValidateCSPToken(directive, token)
}

func validateCSPToken(directive, token string) error {
	if token == "" {
		return fmt.Errorf("empty value for CSP directive %s", directive)
	}
	if strings.ContainsAny(token, " \t\r\n;") {
		return fmt.Errorf("unallowed value %q for directive %s", token, directive)
	}
	if err := ValidateValueCharset(directive, token); err != nil {
		return err
	}

	quoted := strings.HasPrefix(token, "'") || strings.HasSuffix(token, "'")
	if quoted {
		if len(token) < 2 || !strings.HasPrefix(token, "'") || !strings.HasSuffix(token, "'") {
			return fmt.Errorf("invalid quoted value %q for CSP directive %s", token, directive)
		}

		switch token {
		case "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'",
			"'strict-dynamic'", "'report-sample'", "'wasm-unsafe-eval'",
			"'trusted-types-eval'", "'unsafe-allow-redirects'":
			return nil
		}

		if cspNoncePattern.MatchString(token) || cspHashPattern.MatchString(token) ||
			cspQuotedWordPattern.MatchString(token) {
			return nil
		}

		return fmt.Errorf("invalid quoted source %q for CSP directive %s", token, directive)
	}

	return ValidateCSPSource(token)
}

// ValidateCSPSource validates an unquoted CSP source expression or a scheme
// token. Wildcard hosts and source paths are valid in the CSP domain.
func ValidateCSPSource(source string) error {
	if source == "" {
		return fmt.Errorf("source is empty")
	}
	if err := validateHeaderChars(source); err != nil {
		return err
	}
	if source == "*" || schemePattern.MatchString(source) {
		return nil
	}

	// Host sources may omit a scheme ("*.example.com/path") and therefore are
	// not always parseable as absolute URLs. The character check plus a small
	// set of structural rules is enough to reject directive injection.
	if strings.ContainsAny(source, " \t\r\n\x00;") {
		return fmt.Errorf("invalid CSP source %q", source)
	}
	if strings.HasPrefix(source, ".") || strings.HasSuffix(source, ".") {
		return fmt.Errorf("invalid CSP source %q", source)
	}

	return nil
}

// ValidateSource validates a source in a header-specific domain. CSP accepts
// wildcard host sources and source expressions; Permissions-Policy accepts the
// special self/src/* tokens and exact quoted/unquoted origins.
func ValidateSource(domain Type, source string) error {
	switch domain {
	case PermissionsPolicy:
		source = strings.TrimSpace(source)
		switch source {
		case "*", "self", "src", `"self"`, `"src"`:
			return nil
		}
		source = strings.Trim(source, `"`)
		return ValidateOrigin(source)
	default:
		return ValidateCSPSource(source)
	}
}

// ValidatePermissionsPolicy validates a serialized modern Permissions-Policy
// header. Feature names are syntax-checked rather than matched against a fixed
// list because browser feature names continue to evolve.
func ValidatePermissionsPolicy(policy string) error {
	if strings.TrimSpace(policy) == "" {
		return fmt.Errorf("permissions policy is empty")
	}
	if err := validateHeaderChars(policy); err != nil {
		return fmt.Errorf("invalid permissions policy: %w", err)
	}
	if strings.Contains(policy, ";") {
		return fmt.Errorf("invalid permissions policy %q: directives must be comma-separated, not semicolon-separated", policy)
	}

	seen := make(map[string]struct{})
	for _, assignment := range strings.Split(policy, ",") {
		assignment = strings.TrimSpace(assignment)
		if assignment == "" {
			return fmt.Errorf("permissions policy contains an empty directive")
		}

		equals := strings.IndexByte(assignment, '=')
		if equals <= 0 {
			return fmt.Errorf("invalid permissions policy directive %q: expected feature=allowlist", assignment)
		}

		feature := strings.TrimSpace(assignment[:equals])
		allowlist := strings.TrimSpace(assignment[equals+1:])
		if !featureNamePattern.MatchString(feature) {
			return fmt.Errorf("invalid permissions feature name %q", feature)
		}
		if _, duplicate := seen[feature]; duplicate {
			return fmt.Errorf("duplicate permissions feature %q", feature)
		}
		seen[feature] = struct{}{}
		if err := ValidatePermissionsAllowlist(allowlist); err != nil {
			return fmt.Errorf("invalid allowlist for permissions feature %q: %w", feature, err)
		}
	}

	return nil
}

// ValidatePermissionsAllowlist validates the right-hand side of one
// Permissions-Policy feature assignment.
func ValidatePermissionsAllowlist(allowlist string) error {
	allowlist = strings.TrimSpace(allowlist)
	if allowlist == "" {
		return fmt.Errorf("allowlist is empty")
	}
	if allowlist == "*" {
		return nil
	}
	if allowlist == "()" {
		return nil
	}

	if !strings.HasPrefix(allowlist, "(") || !strings.HasSuffix(allowlist, ")") || len(allowlist) < 2 {
		return fmt.Errorf("allowlist %q must be *, (), or a parenthesized list", allowlist)
	}

	inner := strings.TrimSpace(allowlist[1 : len(allowlist)-1])
	if inner == "" {
		return nil
	}

	for _, item := range strings.Fields(inner) {
		switch item {
		case "self", "src":
			continue
		}

		if strings.HasPrefix(item, "\"") || strings.HasSuffix(item, "\"") {
			if len(item) < 2 || !strings.HasPrefix(item, "\"") || !strings.HasSuffix(item, "\"") {
				return fmt.Errorf("invalid quoted origin %q", item)
			}
			origin := item[1 : len(item)-1]
			if err := ValidateOrigin(origin); err != nil {
				return err
			}
			continue
		}

		return fmt.Errorf("invalid allowlist item %q: expected self, src, or a quoted origin", item)
	}

	return nil
}

// ValidateOrigin validates an exact web origin used by Permissions-Policy.
// Unlike CSP host sources, origins may not contain wildcard hosts or paths.
func ValidateOrigin(origin string) error {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return fmt.Errorf("origin is empty")
	}
	if origin == "*" || strings.Contains(origin, "*") {
		return fmt.Errorf("wildcard origin %q is not an exact Permissions-Policy origin; use the bare * allowlist only when all origins are intended", origin)
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin %q: %w", origin, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid origin %q: expected scheme://host[:port]", origin)
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("invalid origin %q: only http and https origins are supported", origin)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid origin %q: origins must not contain credentials, query strings, or fragments", origin)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("invalid origin %q: origins must not contain a path", origin)
	}
	if hostname := parsed.Hostname(); hostname == "" {
		return fmt.Errorf("invalid origin %q: host is required", origin)
	}
	if portText := parsed.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid origin %q: invalid port %q", origin, portText)
		}
	}

	return nil
}

// ValidateFrameOptions validates X-Frame-Options. DENY and SAMEORIGIN are the
// widely supported values; ALLOW-FROM is retained for legacy configuration.
func ValidateFrameOptions(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("X-Frame-Options value is empty")
	}
	if err := validateHeaderChars(value); err != nil {
		return fmt.Errorf("invalid X-Frame-Options value: %w", err)
	}

	upper := strings.ToUpper(value)
	if upper == "DENY" || upper == "SAMEORIGIN" {
		return nil
	}

	if strings.HasPrefix(upper, "ALLOW-FROM ") {
		origin := strings.TrimSpace(value[len("ALLOW-FROM "):])
		origin = strings.TrimPrefix(origin, "=")
		if err := ValidateOrigin(origin); err == nil {
			return nil
		} else if parsed, parseErr := url.Parse(origin); parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid X-Frame-Options ALLOW-FROM value %q", value)
		}
		return nil
	}

	return fmt.Errorf("invalid X-Frame-Options value %q: expected DENY, SAMEORIGIN, or ALLOW-FROM <origin>", value)
}

// ValidateContentTypeOptions validates X-Content-Type-Options.
func ValidateContentTypeOptions(value string) error {
	value = strings.TrimSpace(value)
	if !strings.EqualFold(value, "nosniff") {
		return fmt.Errorf("invalid X-Content-Type-Options value %q: expected nosniff", value)
	}
	return nil
}

// ValidateFeaturePolicy performs legacy Feature-Policy validation. Semicolons
// are legal separators in this deprecated header grammar.
func ValidateFeaturePolicy(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("feature policy is empty")
	}
	return validateHeaderChars(value)
}

// ValidateXSSProtection validates the legacy X-XSS-Protection value loosely
// enough to retain its report= parameter syntax.
func ValidateXSSProtection(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("X-XSS-Protection value is empty")
	}
	return validateHeaderChars(value)
}

func validateHeaderChars(value string) error {
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char == '\t' {
			continue
		}
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("value contains an invalid control character")
		}
	}
	return nil
}
