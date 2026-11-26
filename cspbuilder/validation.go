package cspbuilder

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	directiveNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	nonceSourcePattern   = regexp.MustCompile(`^'nonce-[A-Za-z0-9+/_-]+={0,2}'$`)
	hashSourcePattern    = regexp.MustCompile(`^'(sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'$`)
	quotedKeywordPattern = regexp.MustCompile(`^'[A-Za-z][A-Za-z0-9-]*'$`)
	reportToPattern      = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
)

func validateDirectiveName(name string) error {
	if !directiveNamePattern.MatchString(name) {
		return fmt.Errorf("invalid directive name %q", name)
	}

	return nil
}

// validateValueCharset rejects characters that can terminate a directive or
// value, as well as characters that are not valid in a serialized CSP token.
func validateValueCharset(directive, value string) error {
	if value == "" {
		return fmt.Errorf("empty value for directive %s", directive)
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

func validateSourceValue(directive, value string) error {
	if err := validateValueCharset(directive, value); err != nil {
		return err
	}

	quoted := strings.HasPrefix(value, "'") || strings.HasSuffix(value, "'")
	if !quoted {
		return nil
	}

	if len(value) < 2 || !strings.HasPrefix(value, "'") || !strings.HasSuffix(value, "'") {
		return fmt.Errorf("unallowed value %s for directive %s", value, directive)
	}

	inner := value[1 : len(value)-1]
	switch inner {
	case "self", "none", "unsafe-inline", "unsafe-eval", "unsafe-hashes",
		"unsafe-allow-redirects", "strict-dynamic", "report-sample",
		"wasm-unsafe-eval", "trusted-types-eval":
		return nil
	}

	if strings.HasPrefix(inner, "nonce-") {
		if nonceSourcePattern.MatchString(value) {
			return nil
		}

		return fmt.Errorf("unallowed value %s for directive %s", value, directive)
	}

	if strings.HasPrefix(inner, "sha256-") || strings.HasPrefix(inner, "sha384-") || strings.HasPrefix(inner, "sha512-") {
		if hashSourcePattern.MatchString(value) {
			return nil
		}

		return fmt.Errorf("unallowed value %s for directive %s", value, directive)
	}

	// Keep quoted keyword values forward-compatible while still requiring a
	// restricted token shape.
	if quotedKeywordPattern.MatchString(value) {
		return nil
	}

	return fmt.Errorf("unallowed value %s for directive %s", value, directive)
}

func validateReportToValue(value string) error {
	if !reportToPattern.MatchString(value) {
		return fmt.Errorf("unallowed value %s for directive %s", value, ReportTo)
	}

	return nil
}

func validateReportURIValue(value string) error {
	if err := validateValueCharset(ReportURI, value); err != nil {
		return err
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("unallowed value %s for directive %s", value, ReportURI)
	}

	if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("unallowed value %s for directive %s", value, ReportURI)
	}

	if strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https") {
		if parsed.Host == "" {
			return fmt.Errorf("unallowed value %s for directive %s", value, ReportURI)
		}
	}

	if strings.HasPrefix(value, "//") && parsed.Host == "" {
		return fmt.Errorf("unallowed value %s for directive %s", value, ReportURI)
	}

	return nil
}

// validatePolicyStructure re-parses the serialized policy and compares it with
// the configured directives. It is a final defense against values that manage
// to introduce additional directives or values after their own validation.
func validatePolicyStructure(policy string, directives map[string][]string) error {
	if policy == "" {
		if len(directives) != 0 {
			return fmt.Errorf("invalid policy: empty serialized policy")
		}

		return nil
	}

	if strings.ContainsAny(policy, "\r\n\x00") {
		return fmt.Errorf("invalid policy: contains control characters")
	}

	segments := strings.Split(policy, ";")
	if len(segments) != len(directives) {
		return fmt.Errorf("invalid policy: expected %d directives, found %d", len(directives), len(segments))
	}

	seen := make(map[string]struct{}, len(segments))

	for _, segment := range segments {
		fields := strings.Fields(strings.TrimSpace(segment))
		if len(fields) == 0 {
			return fmt.Errorf("invalid policy: empty directive")
		}

		name := fields[0]
		if err := validateDirectiveName(name); err != nil {
			return err
		}

		expected, ok := directives[name]
		if !ok {
			return fmt.Errorf("invalid policy: unexpected directive %s", name)
		}

		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("invalid policy: duplicate directive %s", name)
		}
		seen[name] = struct{}{}

		if len(fields)-1 != len(expected) {
			return fmt.Errorf("invalid policy: expected %d values for directive %s, found %d", len(expected), name, len(fields)-1)
		}

		for i, value := range expected {
			if fields[i+1] != value {
				return fmt.Errorf("invalid policy: unexpected value %q for directive %s", fields[i+1], name)
			}
		}
	}

	return nil
}
