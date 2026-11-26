package secure

import (
	"net/http/httptest"
	"testing"

	"github.com/unrolled/secure/permissionspolicybuilder"
)

func TestHeaderValidationMatrix(t *testing.T) {
	valid := []struct{ h, v string }{
		{cspHeader, "default-src 'self'; script-src $NONCE"},
		{permissionsPolicyHeader, "geolocation=(self), camera=(), fullscreen=(self \"https://example.com\")"},
		{frameOptionsHeader, "SAMEORIGIN"},
		{frameOptionsHeader, "DENY"},
		{contentTypeHeader, "nosniff"},
		{featurePolicyHeader, "vibrate 'none';"},
	}
	for _, tc := range valid {
		if err := ValidateHeaderValue(tc.h, tc.v); err != nil {
			t.Fatalf("expected %q %q valid: %v", tc.h, tc.v, err)
		}
	}

	invalid := []struct{ h, v string }{
		{permissionsPolicyHeader, "geolocation=(self); camera=()"},
		{permissionsPolicyHeader, "geolocation=(*)"},
		{permissionsPolicyHeader, "geolocation=(https://example.com)"},
		{permissionsPolicyHeader, "geolocation=(\"https://*.example.com\")"},
		{frameOptionsHeader, "ALLOWALL"},
		{contentTypeHeader, "sniff"},
		{cspHeader, "default-src 'self'; bad-directive *"},
	}
	for _, tc := range invalid {
		if err := ValidateHeaderValue(tc.h, tc.v); err == nil {
			t.Fatalf("expected %q %q invalid", tc.h, tc.v)
		}
	}
}

func TestStartupValidationAndHeaderWriting(t *testing.T) {
	for _, options := range []Options{
		{PermissionsPolicy: "geolocation=(self); camera=()"},
		{CustomFrameOptionsValue: "nope"},
		{ContentSecurityPolicy: "bad-directive *"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected panic for %#v", options)
				}
			}()
			New(options)
		}()
	}

	s := New(Options{PermissionsPolicy: "geolocation=(self)"})
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(rec, req)
	if got := rec.Header().Get("Permissions-Policy"); got != "geolocation=(self)" {
		t.Fatalf("got %q", got)
	}
}

func TestPermissionsPolicyStructuredBuilder(t *testing.T) {
	b := permissionspolicybuilder.Builder{Directives: map[string][]string{
		"camera":      {},
		"geolocation": {"self"},
		"fullscreen":  {"self", "https://example.com"},
		"payment":     {"*"},
	}}
	got, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	want := "camera=(), fullscreen=(self \"https://example.com\"), geolocation=(self), payment=*"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestInternalCompatibilitySurface(t *testing.T) {
	_ = []interface{}{
		cspHeaderType,
		contentSecurityPolicyHeaderType,
		permissionsPolicyHeaderType,
		permissionsPolicyType,
		frameOptionsHeaderType,
		frameOptionsType,
		contentTypeOptionsHeaderType,
		contentTypeOptionsType,
		permissionsPolicySelf,
		permissionsPolicySrc,
		permissionsPolicyWildcard,
		permissionsPolicyNone,
	}

	_ = []interface{}{
		validateHeader,
		validateSecurityHeader,
		validateHeaderForType,
		validateHeaderValueForType,
		validateSecurityHeaderValue,
		validateFeatureName,
		validatePermissionName,
		validateCSP,
		validateContentSecurityPolicy,
		validatePermissionsPolicy,
		validatePermissionPolicy,
		validateFrameOptions,
		validateXFrameOptions,
		validateContentTypeOptions,
		validateXContentTypeOptions,
		validateSource,
	}

	_ = newPermissionsPolicyBuilder()
	_ = newPermissionPolicyBuilder()

	var (
		_ policyBuilder
		_ permissionsPolicyBuilder
		_ permissionPolicyBuilder
		_ permissionsPolicy
		_ permissionPolicy
	)

	if err := validateFeatureName(permissionspolicybuilder.Geolocation); err != nil {
		t.Fatal(err)
	}
	if err := validateSource("https://example.com"); err != nil {
		t.Fatal(err)
	}
}
