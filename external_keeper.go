package httpkeeper

import (
	"fmt"
	"net/http"
)

var (
	defaultAllowedRequestHeaders       = []string{"Authorization", "Cookie", "From", "Proxy-Authorization", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}
	defaultAllowedAuthorizationHeaders = []string{"Location", "Authorization", "Proxy-Authenticate", "Set-cookie", "WWW-Authenticate"}
)

const bearerScheme string = "Bearer "

type externalkeeperAuth struct {
	h    http.Handler
	opts ExternalKeeperOptions
}

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

func (o externalkeeperAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r == nil {
		o.opts.InternalServerErrorHandler.ServeHTTP(w, r)
	}

	url := fmt.Sprintf("%s://%s/%s/%s", o.opts.Protocol, o.opts.AuthService, o.opts.PathPrefix, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, url, nil)
	proxyReq.Header = make(http.Header)
	for _, h := range o.opts.AllowedRequestHeaders {
		proxyReq.Header[h] = r.Header[h]
	}

	httpClient := http.Client{}
	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		return
	}

	if resp.StatusCode == http.StatusOK {

	}

	for h, val := range resp.Header {
		r.Header[h] = val
	}

	defer resp.Body.Close()
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

func ExternalAuth(opts ExternalKeeperOptions) func(http.Handler) http.Handler {
	fn := func(h http.Handler) http.Handler {
		return externalkeeperAuth{h, opts}
	}
	return fn
}

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

func (opts *ExternalKeeperOptions) WithAllowedRequestHeaders(headers []string) *ExternalKeeperOptions {
	opts.AllowedRequestHeaders = append(opts.AllowedRequestHeaders, headers...)
	return opts
}

func (opts *ExternalKeeperOptions) WithAllowedAuthorizationHeaders(headers []string) *ExternalKeeperOptions {
	opts.AllowedAuthorizationHeaders = append(opts.AllowedAuthorizationHeaders, headers...)
	return opts
}

func (opts *ExternalKeeperOptions) WithBody(allowPartialBody bool, maxBodyBytes int) *ExternalKeeperOptions {
	opts.IncludeBody = true
	opts.AllowPartialBody = allowPartialBody
	opts.MaxBodyBytes = maxBodyBytes
	return opts
}

func (opts *ExternalKeeperOptions) WithNotFoundHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.NotFoundHandler = http.HandlerFunc(defaultNotFoundHandler)
	}
	opts.NotFoundHandler = h
	return opts
}

func (opts *ExternalKeeperOptions) WithForbiddenHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.ForbiddenHandler = http.HandlerFunc(defaultForbiddenHandler)
	}
	opts.ForbiddenHandler = h
	return opts
}

func (opts *ExternalKeeperOptions) WithUnauthorizedHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	opts.UnauthorizedHandler = h
	return opts
}

func (opts *ExternalKeeperOptions) WithInternalServerErrorHandler(h http.Handler) *ExternalKeeperOptions {
	if h == nil {
		opts.InternalServerErrorHandler = http.HandlerFunc(defaultInternalServerErrorHandler)
	}
	opts.InternalServerErrorHandler = h
	return opts
}
