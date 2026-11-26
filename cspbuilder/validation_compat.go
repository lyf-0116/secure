package cspbuilder

import (
	"github.com/unrolled/secure/headervalidator"
)

func validateDirectiveName(name string) error {
	return headervalidator.ValidateCSPDirectiveName(name)
}

func validateSourceValue(directive, value string) error {
	if err := validateValueCharset(directive, value); err != nil {
		return err
	}
	return headervalidator.ValidateCSPToken(directive, value)
}

func validateValueCharset(directive, value string) error {
	return headervalidator.ValidateValueCharset(directive, value)
}
