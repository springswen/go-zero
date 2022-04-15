package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/dgrijalva/jwt-go"
	"github.com/springswen/go-zero/core/logx"
	"github.com/springswen/go-zero/rest/token"
)

const (
	jwtAudience    = "aud"
	jwtExpire      = "exp"
	jwtId          = "jti"
	jwtIssueAt     = "iat"
	jwtIssuer      = "iss"
	jwtNotBefore   = "nbf"
	jwtSubject     = "sub"
	noDetailReason = "no detail reason"
)

var (
	errInvalidToken = errors.New("invalid auth token")
	errNoClaims     = errors.New("no auth params")
)

type (
	// A AuthorizeOptions is authorize options.
	AuthorizeOptions struct {
		PrevSecret string
		Callback   UnauthorizedCallback
		Blacklist  BlacklistCallback
	}

	BlacklistCallback func(jwtId string, userId int64) bool
	// UnauthorizedCallback defines the method of unauthorized callback.
	UnauthorizedCallback func(w http.ResponseWriter, r *http.Request, err error)
	// AuthorizeOption defines the method to customize an AuthorizeOptions.
	AuthorizeOption func(opts *AuthorizeOptions)
)

// Authorize returns an authorize middleware.
func Authorize(secret string, opts ...AuthorizeOption) func(http.Handler) http.Handler {
	var authOpts AuthorizeOptions
	for _, opt := range opts {
		opt(&authOpts)
	}

	parser := token.NewTokenParser()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := parser.ParseToken(r, secret, authOpts.PrevSecret)
			if err != nil {
				unauthorized(w, r, err, authOpts.Callback)
				return
			}

			if !tok.Valid {
				unauthorized(w, r, errInvalidToken, authOpts.Callback)
				return
			}

			claims, ok := tok.Claims.(jwt.MapClaims)
			if !ok {
				unauthorized(w, r, errNoClaims, authOpts.Callback)
				return
			}

			if authOpts.Blacklist != nil {
				// var ty, k int64
				// switch v := claims[jwtExpire].(type) {
				// case int64:
				// 	ty = v
				// 	k = 1
				// case float64:
				// 	ty = int64(v)
				// 	k = 2
				// case json.Number:
				// 	ty, _ = v.Int64()
				// 	k = 3
				// default:
				// 	k = 4
				// }

				// logx.Infof("Authorize k:%d ty:%d claims:%+v", k, ty, claims)

				jwtId, ok := claims[jwtId].(string)
				if !ok {
					logx.Errorf("Authorize jwtId:%+v", jwtId)
					unauthorized(w, r, errNoClaims, authOpts.Callback)
					return
				}

				userId, err := claims["userId"].(json.Number).Int64()
				if err != nil {
					logx.Errorf("Authorize userId:%+v", userId)
					unauthorized(w, r, errNoClaims, authOpts.Callback)
					return
				}

				if authOpts.Blacklist(jwtId, userId) {
					unauthorized(w, r, errInvalidToken, authOpts.Callback)
					return
				}
			}

			ctx := r.Context()
			for k, v := range claims {
				switch k {
				case jwtAudience, jwtIssueAt, jwtIssuer, jwtNotBefore, jwtSubject:
					// ignore the standard claims
				default:
					ctx = context.WithValue(ctx, k, v)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithPrevSecret returns an AuthorizeOption with setting previous secret.
func WithPrevSecret(secret string) AuthorizeOption {
	return func(opts *AuthorizeOptions) {
		opts.PrevSecret = secret
	}
}

func WithBlacklistCallback(callback BlacklistCallback) AuthorizeOption {
	return func(opts *AuthorizeOptions) {
		opts.Blacklist = callback
	}
}

// WithUnauthorizedCallback returns an AuthorizeOption with setting unauthorized callback.
func WithUnauthorizedCallback(callback UnauthorizedCallback) AuthorizeOption {
	return func(opts *AuthorizeOptions) {
		opts.Callback = callback
	}
}

func detailAuthLog(r *http.Request, reason string) {
	// discard dump error, only for debug purpose
	details, _ := httputil.DumpRequest(r, true)
	logx.Errorf("authorize failed: %s\n=> %+v", reason, string(details))
}

func unauthorized(w http.ResponseWriter, r *http.Request, err error, callback UnauthorizedCallback) {
	writer := newGuardedResponseWriter(w)

	if err != nil {
		detailAuthLog(r, err.Error())
	} else {
		detailAuthLog(r, noDetailReason)
	}
	if callback != nil {
		callback(writer, r, err)
	}

	writer.WriteHeader(http.StatusUnauthorized)
}

type guardedResponseWriter struct {
	writer      http.ResponseWriter
	wroteHeader bool
}

func newGuardedResponseWriter(w http.ResponseWriter) *guardedResponseWriter {
	return &guardedResponseWriter{
		writer: w,
	}
}

func (grw *guardedResponseWriter) Flush() {
	if flusher, ok := grw.writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (grw *guardedResponseWriter) Header() http.Header {
	return grw.writer.Header()
}

// Hijack implements the http.Hijacker interface.
// This expands the Response to fulfill http.Hijacker if the underlying http.ResponseWriter supports it.
func (grw *guardedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacked, ok := grw.writer.(http.Hijacker); ok {
		return hijacked.Hijack()
	}

	return nil, nil, errors.New("server doesn't support hijacking")
}

func (grw *guardedResponseWriter) Write(body []byte) (int, error) {
	return grw.writer.Write(body)
}

func (grw *guardedResponseWriter) WriteHeader(statusCode int) {
	if grw.wroteHeader {
		return
	}

	grw.wroteHeader = true
	grw.writer.WriteHeader(statusCode)
}
