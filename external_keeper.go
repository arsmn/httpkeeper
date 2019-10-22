package httpkeeper

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

var (
	defaultAllowedRequestHeaders       = []string{"Authorization", "Cookie", "From", "Proxy-Authorization", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}
	defaultAllowedAuthorizationHeaders = []string{"Location", "Authorization", "Proxy-Authenticate", "Set-cookie", "WWW-Authenticate"}
)

type externalKeeperAuth struct {
	h    http.Handler
	opts *ExternalKeeperOptions
}

// ExternalKeeperOptions stores the configuration for External Authentication
type ExternalKeeperOptions struct {
	AuthService                 string
	PathPrefix                  string
	Protocol                    string
	AllowedRequestHeaders       []string
	AllowedAuthorizationHeaders []string
	IncludeBody                 bool
	MaxBodyBytes                int
	AllowPartialBody            bool
	NotFoundHandler             http.Handler
	ForbiddenHandler            http.Handler
	UnauthorizedHandler         http.Handler
	InternalServerErrorHandler  http.Handler
}

// ServeHTTP satisfies the http.Handler interface for externalkeeperAuth
func (o externalKeeperAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r == nil {
		o.opts.InternalServerErrorHandler.ServeHTTP(w, r)
		return
	}

	reqBody := new(bytes.Reader)
	if o.opts.IncludeBody {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			o.opts.InternalServerErrorHandler.ServeHTTP(w, r)
			return
		}
		reqBody = bytes.NewReader(body)
	}

	url := fmt.Sprintf("%s://%s/%s/%s", o.opts.Protocol, o.opts.AuthService, o.opts.PathPrefix, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, url, reqBody)
	proxyReq.Header = make(http.Header)
	for _, h := range o.opts.AllowedRequestHeaders {
		proxyReq.Header[h] = r.Header[h]
	}

	httpClient := http.Client{}
	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		o.opts.InternalServerErrorHandler.ServeHTTP(w, r)
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		for _, h := range o.opts.AllowedAuthorizationHeaders {
			r.Header[h] = resp.Header[h]
		}
		o.h.ServeHTTP(w, r)
	case http.StatusUnauthorized:
		o.opts.UnauthorizedHandler.ServeHTTP(w, r)
	case http.StatusForbidden:
		o.opts.ForbiddenHandler.ServeHTTP(w, r)
	case http.StatusInternalServerError:
		o.opts.InternalServerErrorHandler.ServeHTTP(w, r)
	default:
		o.opts.InternalServerErrorHandler.ServeHTTP(w, r)
	}
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func defaultInternalServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func defaultNotFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func defaultForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

// ExternalAuth provides HTTP middleware for protecting URIs with external service
func ExternalAuth(opts *ExternalKeeperOptions) func(http.Handler) http.Handler {
	fn := func(h http.Handler) http.Handler {
		return externalKeeperAuth{h, opts}
	}
	return fn
}

// NewExternalKeeperOptions return an ExternalKeeperOptions with default values
func NewExternalKeeperOptions(authService, pathPrefix, protocol string) *ExternalKeeperOptions {
	return &ExternalKeeperOptions{
		AuthService:                 authService,
		PathPrefix:                  pathPrefix,
		Protocol:                    protocol,
		AllowedRequestHeaders:       defaultAllowedRequestHeaders,
		AllowedAuthorizationHeaders: defaultAllowedAuthorizationHeaders,
		NotFoundHandler:             http.HandlerFunc(defaultNotFoundHandler),
		ForbiddenHandler:            http.HandlerFunc(defaultForbiddenHandler),
		UnauthorizedHandler:         http.HandlerFunc(defaultUnauthorizedHandler),
		InternalServerErrorHandler:  http.HandlerFunc(defaultInternalServerErrorHandler),
	}
}

// WithAllowedRequestHeaders sets AllowedRequestHeaders
func (opts *ExternalKeeperOptions) WithAllowedRequestHeaders(headers []string) *ExternalKeeperOptions {
	opts.AllowedRequestHeaders = append(opts.AllowedRequestHeaders, headers...)
	return opts
}

// WithAllowedAuthorizationHeaders sets AllowedAuthorizationHeaders
func (opts *ExternalKeeperOptions) WithAllowedAuthorizationHeaders(headers []string) *ExternalKeeperOptions {
	opts.AllowedAuthorizationHeaders = append(opts.AllowedAuthorizationHeaders, headers...)
	return opts
}

// WithBody includes body to auth service
func (opts *ExternalKeeperOptions) WithBody(allowPartialBody bool, maxBodyBytes int) *ExternalKeeperOptions {
	opts.IncludeBody = true
	opts.AllowPartialBody = allowPartialBody
	opts.MaxBodyBytes = maxBodyBytes
	return opts
}

// WithNotFoundHandler sets http handler when auth service responses with NotFound (404) status
func (opts *ExternalKeeperOptions) WithNotFoundHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.NotFoundHandler = http.HandlerFunc(defaultNotFoundHandler)
	}
	opts.NotFoundHandler = h
	return opts
}

// WithForbiddenHandler sets http handler when auth service responses with Forbidden (403) status
func (opts *ExternalKeeperOptions) WithForbiddenHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.ForbiddenHandler = http.HandlerFunc(defaultForbiddenHandler)
	}
	opts.ForbiddenHandler = h
	return opts
}

// WithUnauthorizedHandler sets http handler when auth service responses with Unauthorized (401) status
func (opts *ExternalKeeperOptions) WithUnauthorizedHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	opts.UnauthorizedHandler = h
	return opts
}

// WithInternalServerErrorHandler sets http handler when auth service responses with InternalServerError (500) status or any other unhandled status
func (opts *ExternalKeeperOptions) WithInternalServerErrorHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.InternalServerErrorHandler = http.HandlerFunc(defaultInternalServerErrorHandler)
	}
	opts.InternalServerErrorHandler = h
	return opts
}
