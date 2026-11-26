package secure

import "net/http"

// secureHeaderSet is the single write path for headers assembled by the
// middleware. Every value passes the syntax-aware validation layer before it
// reaches the underlying http.Header.
type secureHeaderSet struct {
	http.Header
	errs []error
}

func newSecureHeaderSet() *secureHeaderSet {
	return &secureHeaderSet{Header: make(http.Header)}
}

// Set validates and stores a header. It intentionally has the same name as
// http.Header.Set so existing assembly call sites go through validation without
// introducing a second direct write path.
func (set *secureHeaderSet) Set(name, value string) {
	if err := setSecurityHeader(set.Header, name, value); err != nil {
		set.errs = append(set.errs, err)
	}
}

func (set *secureHeaderSet) error() error {
	if set == nil || len(set.errs) == 0 {
		return nil
	}
	return set.errs[0]
}

func setSecurityHeader(headers http.Header, name, value string) error {
	if err := validateHeaderValue(name, value); err != nil {
		return err
	}
	headers.Set(name, value)
	return nil
}

func mustSetSecurityHeader(headers http.Header, name, value string) {
	if err := setSecurityHeader(headers, name, value); err != nil {
		panic(err)
	}
}
