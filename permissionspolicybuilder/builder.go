// Package permissionspolicybuilder constructs Permissions-Policy headers.
package permissionspolicybuilder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/unrolled/secure/headervalidator"
)

// Common Permissions-Policy feature names. Feature names are not validated
// against this list; the constants are only provided as a convenience.
const (
	Accelerometer              = "accelerometer"
	AmbientLightSensor         = "ambient-light-sensor"
	AttributionReporting       = "attribution-reporting"
	Autoplay                   = "autoplay"
	Bluetooth                  = "bluetooth"
	BrowsingTopics             = "browsing-topics"
	Camera                     = "camera"
	CapturedSurfaceControl     = "captured-surface-control"
	ClipboardRead              = "clipboard-read"
	ClipboardWrite             = "clipboard-write"
	ComputePressure            = "compute-pressure"
	CrossOriginIsolated        = "cross-origin-isolated"
	DisplayCapture             = "display-capture"
	DocumentDomain             = "document-domain"
	EncryptedMedia             = "encrypted-media"
	Fullscreen                 = "fullscreen"
	Gamepad                    = "gamepad"
	Geolocation                = "geolocation"
	Gyroscope                  = "gyroscope"
	HID                        = "hid"
	IdentityCredentialsGet     = "identity-credentials-get"
	IdleDetection              = "idle-detection"
	LocalFonts                 = "local-fonts"
	Magnetometer               = "magnetometer"
	Microphone                 = "microphone"
	MIDI                       = "midi"
	OTPCredentials             = "otp-credentials"
	Payment                    = "payment"
	PictureInPicture           = "picture-in-picture"
	PublicKeyCredentialsCreate = "publickey-credentials-create"
	PublicKeyCredentialsGet    = "publickey-credentials-get"
	ScreenWakeLock             = "screen-wake-lock"
	Serial                     = "serial"
	SpeakerSelection           = "speaker-selection"
	StorageAccess              = "storage-access"
	USBDevice                  = "usb"
	WebShare                   = "web-share"
	WindowManagement           = "window-management"
	XRSpatialTracking          = "xr-spatial-tracking"
)

// Source is an allowlist source. It is a string alias so ordinary string
// slices remain directly usable in Builder maps.
type Source = string

// Policy is a list of allowlist sources for one feature.
type Policy = []Source

// Canonical allowlist keywords.
const (
	SourceSelf     Source = "self"
	SourceSrc      Source = "src"
	SourceAll      Source = "*"
	SourceWildcard Source = "*"
	SourceNone     Source = "none"
)

// Short aliases for canonical allowlist keywords.
const (
	Self     = SourceSelf
	Src      = SourceSrc
	All      = SourceAll
	Wildcard = SourceWildcard
	None     = SourceNone
)

// Builder creates a deterministic Permissions-Policy value.
//
// The map fields are aliases for the same structured input. Directives mirrors
// cspbuilder.Builder; Features and Policies match the terminology commonly
// used for this header.
type Builder struct {
	// Directives maps feature names to allowlist sources.
	Directives map[string][]string

	// Features is an alias for Directives.
	Features map[string][]string

	// FeaturePolicies is an alias for Directives.
	FeaturePolicies map[string][]string

	// Policies is an alias for Directives.
	Policies map[string][]string

	// Policy is an alias for Directives.
	Policy map[string][]string

	// Permission is an alias for Directives.
	Permission map[string][]string

	// Permissions is an alias for Directives.
	Permissions map[string][]string

	// PermissionsPolicies is an alias for Directives.
	PermissionsPolicies map[string][]string

	// AllowLists is an alias for Directives.
	AllowLists map[string][]string

	// Allowlist is an alias for Directives.
	Allowlist map[string][]string

	// Sources is an alias for Directives.
	Sources map[string][]string

	// Origins is an alias for Directives.
	Origins map[string][]string

	// Values is an alias for Directives.
	Values map[string][]string
}

// New returns an initialized Builder.
func New() *Builder {
	return &Builder{Directives: make(map[string][]string)}
}

// NewBuilder returns an initialized Builder. It is an alias for New.
func NewBuilder() *Builder {
	return New()
}

// NewPermissionsPolicyBuilder is an alias for New.
func NewPermissionsPolicyBuilder() *Builder {
	return New()
}

// NewPolicyBuilder is an alias for New.
func NewPolicyBuilder() *Builder {
	return New()
}

// Build builds a policy from a feature-to-sources map.
func Build(policies map[string][]string) (string, error) {
	return (&Builder{Directives: policies}).Build()
}

// MustBuild builds a policy or panics if it is invalid.
func MustBuild(policies map[string][]string) string {
	policy, err := Build(policies)
	if err != nil {
		panic(err)
	}
	return policy
}

// Add appends sources for feature and returns the builder for chaining.
func (builder *Builder) Add(feature string, sources ...string) *Builder {
	if builder.Directives == nil {
		builder.Directives = make(map[string][]string)
	}
	builder.Directives[feature] = append(builder.Directives[feature], sources...)
	return builder
}

// Allow is an alias for Add.
func (builder *Builder) Allow(feature string, sources ...string) *Builder {
	return builder.Add(feature, sources...)
}

// AddPolicy is an alias for Add.
func (builder *Builder) AddPolicy(feature string, sources ...string) *Builder {
	return builder.Add(feature, sources...)
}

// AllowFeature is an alias for Add.
func (builder *Builder) AllowFeature(feature string, sources ...string) *Builder {
	return builder.Add(feature, sources...)
}

// Set replaces the sources configured for feature.
func (builder *Builder) Set(feature string, sources ...string) *Builder {
	if builder.Directives == nil {
		builder.Directives = make(map[string][]string)
	}
	builder.Directives[feature] = sources
	return builder
}

// WithFeature is a fluent alias for Add.
func (builder *Builder) WithFeature(feature string, sources ...string) *Builder {
	return builder.Add(feature, sources...)
}

// WithPolicy is a fluent alias for Add.
func (builder *Builder) WithPolicy(feature string, sources ...string) *Builder {
	return builder.Add(feature, sources...)
}

// AllowSelf allows feature on the same origin.
func (builder *Builder) AllowSelf(feature string) *Builder {
	return builder.Add(feature, Self)
}

// AllowAll allows feature on every origin.
func (builder *Builder) AllowAll(feature string) *Builder {
	return builder.Add(feature, All)
}

// Deny disables feature for all origins.
func (builder *Builder) Deny(feature string) *Builder {
	return builder.Set(feature)
}

// AllowOrigin adds exact origins to feature.
func (builder *Builder) AllowOrigin(feature string, origins ...string) *Builder {
	return builder.Add(feature, origins...)
}

// AllowOrigins adds exact origins to feature.
func (builder *Builder) AllowOrigins(feature string, origins ...string) *Builder {
	return builder.Add(feature, origins...)
}

// MustBuild is like Build but panics if the policy is invalid.
func (builder *Builder) MustBuild() string {
	policy, err := builder.Build()
	if err != nil {
		panic(err)
	}
	return policy
}

// Build validates every feature and source, then serializes the policy.
func (builder *Builder) Build() (string, error) {
	merged, err := builder.mergedPolicies()
	if err != nil {
		return "", err
	}

	features := make([]string, 0, len(merged))
	for feature := range merged {
		features = append(features, feature)
	}
	sort.Strings(features)

	parts := make([]string, 0, len(features))
	for _, feature := range features {
		allowlist, err := buildAllowlist(feature, merged[feature])
		if err != nil {
			return "", err
		}
		parts = append(parts, feature+"="+allowlist)
	}

	policy := strings.Join(parts, ", ")
	if policy != "" {
		if err := headervalidator.ValidatePermissionsPolicy(policy); err != nil {
			return "", err
		}
	}

	return policy, nil
}

// Validate reports whether the builder can produce a valid header.
func (builder *Builder) Validate() error {
	_, err := builder.Build()
	return err
}

func (builder *Builder) mergedPolicies() (map[string][]string, error) {
	merged := make(map[string][]string)
	maps := []map[string][]string{
		builder.Directives,
		builder.Features,
		builder.FeaturePolicies,
		builder.Policies,
		builder.Policy,
		builder.Permission,
		builder.Permissions,
		builder.PermissionsPolicies,
		builder.AllowLists,
		builder.Allowlist,
		builder.Sources,
		builder.Origins,
		builder.Values,
	}
	for _, policies := range maps {
		for feature, sources := range policies {
			if err := validateFeatureName(feature); err != nil {
				return nil, err
			}
			merged[feature] = append(merged[feature], sources...)
		}
	}
	return merged, nil
}

func validateFeatureName(feature string) error {
	if strings.TrimSpace(feature) == "" {
		return fmt.Errorf("permissions feature name is empty")
	}
	// Reuse the full header parser with a known-valid empty allowlist. This
	// keeps feature-name rules in the shared validation layer.
	return headervalidator.ValidatePermissionsPolicy(feature + "=()")
}

func buildAllowlist(feature string, sources []string) (string, error) {
	if len(sources) == 0 {
		return "()", nil
	}

	items := make([]string, 0, len(sources))
	hasWildcard := false
	hasNone := false

	for _, source := range sources {
		item, kind, err := normalizeSource(source)
		if err != nil {
			return "", fmt.Errorf("invalid source for permissions feature %q: %w", feature, err)
		}
		switch kind {
		case "wildcard":
			hasWildcard = true
		case "none":
			hasNone = true
		default:
			items = append(items, item)
		}
	}

	if hasNone {
		if len(sources) != 1 {
			return "", fmt.Errorf("'none' must be the only source for permissions feature %q", feature)
		}
		return "()", nil
	}
	if hasWildcard {
		if len(sources) != 1 {
			return "", fmt.Errorf("wildcard * must be the only source for permissions feature %q", feature)
		}
		return "*", nil
	}

	if len(items) == 1 && strings.HasPrefix(items[0], "(") && strings.HasSuffix(items[0], ")") {
		return items[0], nil
	}

	if err := headervalidator.ValidatePermissionsAllowlist("(" + strings.Join(items, " ") + ")"); err != nil {
		return "", fmt.Errorf("invalid allowlist for permissions feature %q: %w", feature, err)
	}

	return "(" + strings.Join(items, " ") + ")", nil
}

func normalizeSource(source string) (item string, kind string, err error) {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return "", "", fmt.Errorf("source is empty")
	}

	switch trimmed {
	case "*":
		return "*", "wildcard", nil
	case "none", "'none'":
		return "none", "none", nil
	case "self", "'self'":
		return "self", "token", nil
	case "src", "'src'":
		return "src", "token", nil
	}

	if strings.HasPrefix(trimmed, "(") && strings.HasSuffix(trimmed, ")") {
		if err := headervalidator.ValidatePermissionsAllowlist(trimmed); err != nil {
			return "", "", err
		}
		return trimmed, "raw-allowlist", nil
	}
	if strings.ContainsAny(trimmed, " \t") {
		candidate := "(" + trimmed + ")"
		if err := headervalidator.ValidatePermissionsAllowlist(candidate); err == nil {
			return candidate, "raw-allowlist", nil
		}
	}

	if strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"") && len(trimmed) >= 2 {
		origin := trimmed[1 : len(trimmed)-1]
		if err := headervalidator.ValidateOrigin(origin); err != nil {
			return "", "", err
		}
		return "\"" + origin + "\"", "origin", nil
	}

	// Accept CSP-style single-quoted origins only for the special tokens
	// handled above. A remaining quoted value is not valid PP syntax.
	if strings.HasPrefix(trimmed, "'") || strings.HasSuffix(trimmed, "'") {
		return "", "", fmt.Errorf("Permissions-Policy origins must use double quotes; %q is invalid", source)
	}

	if err := headervalidator.ValidateOrigin(trimmed); err != nil {
		return "", "", err
	}
	return "\"" + strings.TrimSpace(trimmed) + "\"", "origin", nil
}

// Parse validates and parses a serialized Permissions-Policy value into a
// Builder. Quoted origins retain their quotes as source strings.
func Parse(policy string) (*Builder, error) {
	if err := headervalidator.ValidatePermissionsPolicy(policy); err != nil {
		return nil, err
	}

	builder := New()
	for _, assignment := range strings.Split(policy, ",") {
		assignment = strings.TrimSpace(assignment)
		equals := strings.IndexByte(assignment, '=')
		feature := strings.TrimSpace(assignment[:equals])
		allowlist := strings.TrimSpace(assignment[equals+1:])

		switch allowlist {
		case "()":
			builder.Directives[feature] = nil
		case "*":
			builder.Directives[feature] = []string{"*"}
		default:
			inner := strings.TrimSpace(allowlist[1 : len(allowlist)-1])
			builder.Directives[feature] = strings.Fields(inner)
		}
	}

	return builder, nil
}

// MustParse is like Parse but panics on an invalid policy.
func MustParse(policy string) *Builder {
	builder, err := Parse(policy)
	if err != nil {
		panic(err)
	}
	return builder
}
