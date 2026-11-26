// Package permissionspolicy provides a structured builder for the
// Permissions-Policy header. It is an alias of permissionspolicybuilder.
package permissionspolicy

import (
	ppb "github.com/unrolled/secure/permissionspolicybuilder"
)

// Builder constructs a Permissions-Policy header.
type Builder = ppb.Builder

// Source is one allowlist source.
type Source = ppb.Source

// Policy is a list of sources for one feature.
type Policy = ppb.Policy

// Allowlist keyword aliases.
const (
	Self     = ppb.Self
	Src      = ppb.Src
	All      = ppb.All
	Wildcard = ppb.Wildcard
	None     = ppb.None
)

// New returns an initialized builder.
func New() *Builder { return ppb.New() }

// NewBuilder returns an initialized builder.
func NewBuilder() *Builder { return ppb.NewBuilder() }

// NewPermissionsPolicyBuilder returns an initialized builder.
func NewPermissionsPolicyBuilder() *Builder { return ppb.NewPermissionsPolicyBuilder() }

// NewPolicyBuilder returns an initialized builder.
func NewPolicyBuilder() *Builder { return ppb.NewPolicyBuilder() }

// Build builds a policy from a feature-to-sources map.
func Build(policies map[string][]string) (string, error) { return ppb.Build(policies) }

// MustBuild builds a policy or panics.
func MustBuild(policies map[string][]string) string { return ppb.MustBuild(policies) }

// Parse parses and validates a serialized policy.
func Parse(policy string) (*Builder, error) { return ppb.Parse(policy) }

// MustParse parses a policy or panics.
func MustParse(policy string) *Builder { return ppb.MustParse(policy) }

// Feature name constants.
const (
	Accelerometer              = ppb.Accelerometer
	AmbientLightSensor         = ppb.AmbientLightSensor
	AttributionReporting       = ppb.AttributionReporting
	Autoplay                   = ppb.Autoplay
	Bluetooth                  = ppb.Bluetooth
	BrowsingTopics             = ppb.BrowsingTopics
	Camera                     = ppb.Camera
	CapturedSurfaceControl     = ppb.CapturedSurfaceControl
	ClipboardRead              = ppb.ClipboardRead
	ClipboardWrite             = ppb.ClipboardWrite
	ComputePressure            = ppb.ComputePressure
	CrossOriginIsolated        = ppb.CrossOriginIsolated
	DisplayCapture             = ppb.DisplayCapture
	DocumentDomain             = ppb.DocumentDomain
	EncryptedMedia             = ppb.EncryptedMedia
	Fullscreen                 = ppb.Fullscreen
	Gamepad                    = ppb.Gamepad
	Geolocation                = ppb.Geolocation
	Gyroscope                  = ppb.Gyroscope
	HID                        = ppb.HID
	IdentityCredentialsGet     = ppb.IdentityCredentialsGet
	IdleDetection              = ppb.IdleDetection
	LocalFonts                 = ppb.LocalFonts
	Magnetometer               = ppb.Magnetometer
	Microphone                 = ppb.Microphone
	MIDI                       = ppb.MIDI
	OTPCredentials             = ppb.OTPCredentials
	Payment                    = ppb.Payment
	PictureInPicture           = ppb.PictureInPicture
	PublicKeyCredentialsCreate = ppb.PublicKeyCredentialsCreate
	PublicKeyCredentialsGet    = ppb.PublicKeyCredentialsGet
	ScreenWakeLock             = ppb.ScreenWakeLock
	Serial                     = ppb.Serial
	SpeakerSelection           = ppb.SpeakerSelection
	StorageAccess              = ppb.StorageAccess
	USBDevice                  = ppb.USBDevice
	WebShare                   = ppb.WebShare
	WindowManagement           = ppb.WindowManagement
	XRSpatialTracking          = ppb.XRSpatialTracking
)
