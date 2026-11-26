package secure

import (
	"fmt"
	"strings"

	"github.com/unrolled/secure/headervalidator"
	"github.com/unrolled/secure/permissionspolicybuilder"
)

// HeaderType identifies a syntax domain used by the unified header validator.
type HeaderType = headervalidator.Type

// HeaderClass is an alias for HeaderType.
type HeaderClass = headervalidator.Type

// HeaderDomain is an alias for HeaderType.
type HeaderDomain = headervalidator.Type

// HeaderKind is an integer-style header domain for callers that prefer iota
// enumerations over header-name strings.
type HeaderKind int

const (
	UnknownHeaderKind HeaderKind = iota
	CSPHeaderKind
	PermissionsPolicyHeaderKind
	FrameOptionsHeaderKind
	ContentTypeOptionsHeaderKind
)

const (
	// CSPHeaderType is the Content-Security-Policy validation domain.
	CSPHeaderType HeaderType = headervalidator.ContentSecurityPolicy
	// HeaderTypeCSP is an alias for CSPHeaderType.
	HeaderTypeCSP = CSPHeaderType
	// ContentSecurityPolicyHeaderType is an alias for CSPHeaderType.
	ContentSecurityPolicyHeaderType = CSPHeaderType
	// HeaderTypeContentSecurityPolicy is an alias for CSPHeaderType.
	HeaderTypeContentSecurityPolicy = CSPHeaderType
	// CSPReportOnlyHeaderType is the report-only CSP validation domain.
	CSPReportOnlyHeaderType HeaderType = headervalidator.ContentSecurityPolicyReportOnly
	// PermissionsPolicyHeaderType is the Permissions-Policy validation domain.
	PermissionsPolicyHeaderType HeaderType = headervalidator.PermissionsPolicy
	// HeaderTypePermissionsPolicy is an alias.
	HeaderTypePermissionsPolicy = PermissionsPolicyHeaderType
	// FeaturePolicyHeaderType is the deprecated Feature-Policy domain.
	FeaturePolicyHeaderType HeaderType = headervalidator.FeaturePolicy
	// FrameOptionsHeaderType is the X-Frame-Options validation domain.
	FrameOptionsHeaderType HeaderType = headervalidator.FrameOptions
	// HeaderTypeFrameOptions is an alias.
	HeaderTypeFrameOptions = FrameOptionsHeaderType
	// ContentTypeOptionsHeaderType is the X-Content-Type-Options domain.
	ContentTypeOptionsHeaderType HeaderType = headervalidator.ContentTypeOptions
	// HeaderTypeContentTypeOptions is an alias.
	HeaderTypeContentTypeOptions = ContentTypeOptionsHeaderType
)

const (
	cspHeaderType                   = CSPHeaderType
	contentSecurityPolicyHeaderType = CSPHeaderType
	permissionsPolicyHeaderType     = PermissionsPolicyHeaderType
	permissionsPolicyType           = PermissionsPolicyHeaderType
	frameOptionsHeaderType          = FrameOptionsHeaderType
	frameOptionsType                = FrameOptionsHeaderType
	contentTypeOptionsHeaderType    = ContentTypeOptionsHeaderType
	contentTypeOptionsType          = ContentTypeOptionsHeaderType
)

const (
	permissionsPolicySelf     = "self"
	permissionsPolicySrc      = "src"
	permissionsPolicyWildcard = "*"
	permissionsPolicyNone     = "none"
)

// PermissionsPolicyBuilder is the structured Permissions-Policy builder.
type PermissionsPolicyBuilder = permissionspolicybuilder.Builder

// PermissionsPolicy is an alternate name for the structured builder.
type PermissionsPolicy = permissionspolicybuilder.Builder

// PermissionPolicyBuilder is an alternate spelling of PermissionsPolicyBuilder.
type PermissionPolicyBuilder = permissionspolicybuilder.Builder

// PermissionPolicy is an alternate spelling of PermissionsPolicy.
type PermissionPolicy = permissionspolicybuilder.Builder

// NewPermissionsPolicyBuilder returns an initialized Permissions-Policy builder.
func NewPermissionsPolicyBuilder() *PermissionsPolicyBuilder {
	return permissionspolicybuilder.New()
}

// NewPermissionPolicyBuilder is an alternate spelling of
// NewPermissionsPolicyBuilder.
func NewPermissionPolicyBuilder() *PermissionPolicyBuilder {
	return permissionspolicybuilder.New()
}

// BuildPermissionsPolicy builds a Permissions-Policy from a source map.
func BuildPermissionsPolicy(policies map[string][]string) (string, error) {
	return permissionspolicybuilder.Build(policies)
}

// MustBuildPermissionsPolicy builds a Permissions-Policy or panics.
func MustBuildPermissionsPolicy(policies map[string][]string) string {
	return permissionspolicybuilder.MustBuild(policies)
}

func newPermissionsPolicyBuilder() *PermissionsPolicyBuilder {
	return NewPermissionsPolicyBuilder()
}

func newPermissionPolicyBuilder() *PermissionPolicyBuilder {
	return NewPermissionPolicyBuilder()
}

type policyBuilder = permissionspolicybuilder.Builder
type permissionsPolicyBuilder = permissionspolicybuilder.Builder
type permissionPolicyBuilder = permissionspolicybuilder.Builder
type permissionsPolicy = permissionspolicybuilder.Builder
type permissionPolicy = permissionspolicybuilder.Builder

// ValidateHeaderValue validates value using the grammar associated with header.
// header may be a canonical header name or a HeaderType value.
func ValidateHeaderValue(header interface{}, value string) error {
	headerName, err := headerNameFromArg(header)
	if err != nil {
		return err
	}
	return headervalidator.Validate(headerName, value)
}

// ValidateHeader is an alias for ValidateHeaderValue.
func ValidateHeader(header interface{}, value string) error {
	return ValidateHeaderValue(header, value)
}

// ValidateSecurityHeader is an alias for ValidateHeaderValue.
func ValidateSecurityHeader(header interface{}, value string) error {
	return ValidateHeaderValue(header, value)
}

// ValidateHeaderValueByType validates value in an explicit header domain.
func ValidateHeaderValueByType(headerType interface{}, value string) error {
	return ValidateHeaderValue(headerType, value)
}

// ValidateHeaderByType is an alias for ValidateHeaderValueByType.
func ValidateHeaderByType(headerType interface{}, value string) error {
	return ValidateHeaderValueByType(headerType, value)
}

func validateHeaderValue(header interface{}, value string) error {
	return ValidateHeaderValue(header, value)
}

func validateHeader(header interface{}, value string) error {
	return ValidateHeaderValue(header, value)
}

func validateSecurityHeader(header interface{}, value string) error {
	return ValidateHeaderValue(header, value)
}

func validateHeaderForType(headerType interface{}, value string) error {
	return ValidateHeaderValueByType(headerType, value)
}

func validateHeaderValueForType(headerType interface{}, value string) error {
	return ValidateHeaderValueByType(headerType, value)
}

func validateSecurityHeaderValue(header interface{}, value string) error {
	return ValidateHeaderValue(header, value)
}

// HeaderValidator provides a method form of the unified validation layer.
type HeaderValidator struct{}

// NewHeaderValidator returns a HeaderValidator.
func NewHeaderValidator() HeaderValidator { return HeaderValidator{} }

// NewValidator is an alias for NewHeaderValidator.
func NewValidator() HeaderValidator { return HeaderValidator{} }

// Validate validates value for header.
func (HeaderValidator) Validate(header interface{}, value string) error {
	return ValidateHeaderValue(header, value)
}

// ValidateValue is an alias for Validate.
func (v HeaderValidator) ValidateValue(header interface{}, value string) error {
	return v.Validate(header, value)
}

// ValidateType validates value in an explicit domain.
func (HeaderValidator) ValidateType(headerType interface{}, value string) error {
	return ValidateHeaderValueByType(headerType, value)
}

// ValidatePermissionsFeatureName validates only a Permissions-Policy feature
// name. Feature names use their own syntax domain and are not CSP directives.
func ValidatePermissionsFeatureName(feature string) error {
	return headervalidator.ValidatePermissionsPolicy(feature + "=()")
}

// ValidateFeatureName is an alias for ValidatePermissionsFeatureName.
func ValidateFeatureName(feature string) error {
	return ValidatePermissionsFeatureName(feature)
}

func validateFeatureName(feature string) error {
	return ValidatePermissionsFeatureName(feature)
}

func validatePermissionName(feature string) error {
	return ValidatePermissionsFeatureName(feature)
}

func validateContentSecurityPolicy(value string) error {
	return headervalidator.ValidateCSP(value)
}

func validateCSP(value string) error {
	return headervalidator.ValidateCSP(value)
}

func validatePermissionsPolicy(value string) error {
	return headervalidator.ValidatePermissionsPolicy(value)
}

func validatePermissionPolicy(value string) error {
	return headervalidator.ValidatePermissionsPolicy(value)
}

func validateFrameOptions(value string) error {
	return headervalidator.ValidateFrameOptions(value)
}

func validateXFrameOptions(value string) error {
	return headervalidator.ValidateFrameOptions(value)
}

func validateContentTypeOptions(value string) error {
	return headervalidator.ValidateContentTypeOptions(value)
}

func validateXContentTypeOptions(value string) error {
	return headervalidator.ValidateContentTypeOptions(value)
}

// ValidateContentSecurityPolicy validates a raw CSP header value.
func ValidateContentSecurityPolicy(value string) error {
	return validateContentSecurityPolicy(value)
}

// ValidatePermissionsPolicyValue validates a raw Permissions-Policy value.
func ValidatePermissionsPolicyValue(value string) error {
	return validatePermissionsPolicy(value)
}

// ValidateFrameOptionsValue validates an X-Frame-Options value.
func ValidateFrameOptionsValue(value string) error {
	return validateFrameOptions(value)
}

// ValidateContentTypeOptionsValue validates an X-Content-Type-Options value.
func ValidateContentTypeOptionsValue(value string) error {
	return validateContentTypeOptions(value)
}

// ValidateSource validates a CSP-style source expression. With two arguments,
// the first selects the header domain:
// ValidateSource("Permissions-Policy", "https://example.com").
func ValidateSource(args ...interface{}) error {
	switch len(args) {
	case 1:
		source, err := stringFromArg(args[0])
		if err != nil {
			return err
		}
		return headervalidator.ValidateCSPSource(source)
	case 2:
		var domainArg, sourceArg interface{}
		if isHeaderSelector(args[0]) {
			domainArg, sourceArg = args[0], args[1]
		} else if isHeaderSelector(args[1]) {
			domainArg, sourceArg = args[1], args[0]
		} else {
			// Preserve the common ValidateSource(domain, source) calling
			// convention even when both arguments are plain strings.
			domainArg, sourceArg = args[0], args[1]
		}
		domain, domainErr := headerNameFromArg(domainArg)
		source, sourceErr := stringFromArg(sourceArg)
		if domainErr != nil || sourceErr != nil {
			if sourceErr != nil {
				return sourceErr
			}
			return domainErr
		}
		return headervalidator.ValidateSource(headervalidator.Type(domain), source)
	default:
		return fmt.Errorf("invalid source validation arguments")
	}
}

func validateSource(args ...interface{}) error {
	return ValidateSource(args...)
}

func headerNameFromArg(header interface{}) (string, error) {
	switch value := header.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "csp":
			return cspHeader, nil
		case "permissions", "permission-policy":
			return permissionsPolicyHeader, nil
		case "frame", "frame-options":
			return frameOptionsHeader, nil
		case "content-type", "content-type-options", "nosniff":
			return contentTypeHeader, nil
		default:
			return value, nil
		}
	case headervalidator.Type:
		return string(value), nil
	case HeaderKind:
		switch value {
		case CSPHeaderKind:
			return cspHeader, nil
		case PermissionsPolicyHeaderKind:
			return permissionsPolicyHeader, nil
		case FrameOptionsHeaderKind:
			return frameOptionsHeader, nil
		case ContentTypeOptionsHeaderKind:
			return contentTypeHeader, nil
		default:
			return "", fmt.Errorf("unknown header kind %d", value)
		}
	case fmt.Stringer:
		return value.String(), nil
	default:
		return "", fmt.Errorf("unsupported header selector %T", header)
	}
}

func stringFromArg(value interface{}) (string, error) {
	switch value := value.(type) {
	case string:
		return value, nil
	case fmt.Stringer:
		return value.String(), nil
	default:
		return "", fmt.Errorf("expected string, got %T", value)
	}
}

func isHeaderSelector(value interface{}) bool {
	switch value.(type) {
	case headervalidator.Type, HeaderKind:
		return true
	}

	text, err := stringFromArg(value)
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
	case strings.ToLower(string(headervalidator.ContentSecurityPolicy)),
		strings.ToLower(string(headervalidator.ContentSecurityPolicyReportOnly)),
		strings.ToLower(string(headervalidator.PermissionsPolicy)),
		"csp", "permissions", "permission-policy":
		return true
	default:
		return false
	}
}

// ValidateOrigin validates an exact Permissions-Policy origin.
func ValidateOrigin(origin string) error {
	return headervalidator.ValidateOrigin(origin)
}

// Validate checks all security-header configuration values that can be
// rejected before the first request. New calls this method and panics on an
// error, matching the existing AllowedHostsAreRegex startup behavior.
func (o Options) Validate() error {
	return validateOptions(o)
}

// ValidateHeaders validates security-header values. It is an alias for Validate.
func (o Options) ValidateHeaders() error {
	return o.Validate()
}

// Validate checks the middleware configuration.
func (s *Secure) Validate() error {
	if s == nil {
		return fmt.Errorf("secure middleware is nil")
	}
	return validateOptions(s.opt)
}

// ValidateHeaders validates middleware header configuration.
func (s *Secure) ValidateHeaders() error {
	return s.Validate()
}

// ValidateOptions validates a Options value without constructing Secure.
func ValidateOptions(options Options) error {
	return validateOptions(options)
}

// ValidateConfig is an alias for ValidateOptions.
func ValidateConfig(options Options) error {
	return validateOptions(options)
}

// ValidateSecureOptions is an alias for ValidateOptions.
func ValidateSecureOptions(options Options) error {
	return validateOptions(options)
}

// NewSecure constructs middleware and returns startup validation errors
// instead of panicking.
func NewSecure(options ...Options) (s *Secure, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if validationErr, ok := recovered.(error); ok {
				err = validationErr
				return
			}
			err = fmt.Errorf("%v", recovered)
		}
	}()

	s = New(options...)
	return s, nil
}

// NewWithError is an alias for NewSecure.
func NewWithError(options ...Options) (*Secure, error) {
	return NewSecure(options...)
}

// NewE is an alias for NewSecure.
func NewE(options ...Options) (*Secure, error) {
	return NewSecure(options...)
}

func validateOptions(options Options) error {
	validations := []struct {
		header string
		value  string
	}{
		{cspHeader, options.ContentSecurityPolicy},
		{cspReportOnlyHeader, options.ContentSecurityPolicyReportOnly},
		{permissionsPolicyHeader, options.PermissionsPolicy},
		{frameOptionsHeader, options.CustomFrameOptionsValue},
		{xssProtectionHeader, options.CustomBrowserXssValue},
		{featurePolicyHeader, options.FeaturePolicy},
		{referrerPolicyHeader, options.ReferrerPolicy},
		{coopHeader, options.CrossOriginOpenerPolicy},
		{coepHeader, options.CrossOriginEmbedderPolicy},
		{corpHeader, options.CrossOriginResourcePolicy},
		{permittedCrossDomainPolicies, options.XPermittedCrossDomainPolicies},
	}

	for _, validation := range validations {
		if validation.value == "" {
			continue
		}
		if err := ValidateHeaderValue(validation.header, validation.value); err != nil {
			return fmt.Errorf("invalid %s configuration: %w", validation.header, err)
		}
	}

	if options.FrameDeny && options.CustomFrameOptionsValue == "" {
		if err := ValidateHeaderValue(frameOptionsHeader, frameOptionsValue); err != nil {
			return fmt.Errorf("invalid %s configuration: %w", frameOptionsHeader, err)
		}
	}
	if options.ContentTypeNosniff {
		if err := ValidateHeaderValue(contentTypeHeader, contentTypeValue); err != nil {
			return fmt.Errorf("invalid %s configuration: %w", contentTypeHeader, err)
		}
	}
	if options.BrowserXssFilter && options.CustomBrowserXssValue == "" {
		if err := ValidateHeaderValue(xssProtectionHeader, xssProtectionValue); err != nil {
			return fmt.Errorf("invalid %s configuration: %w", xssProtectionHeader, err)
		}
	}

	return nil
}
