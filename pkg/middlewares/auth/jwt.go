package auth

import (
	"context"
	"encoding/json"
	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares"
	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/dgrijalva/jwt-go/request"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	jwtTypeName = "JwtIntrospection"
)

type jwtIntrospection struct {
	next         http.Handler
	name         string
	endpoint     string
	clientId     string
	clientSecret string
}

func NewJwtIntrospection(ctx context.Context, next http.Handler, config dynamic.JwtIntrospection, name string) (http.Handler, error) {
	log.FromContext(middlewares.GetLoggerCtx(ctx, name, jwtTypeName)).Debug("Creating middleware")
	a := &jwtIntrospection{
		next:         next,
		name:         name,
		endpoint:     config.Endpoint,
		clientId:     config.ClientId,
		clientSecret: config.ClientSecret,
	}
	return a, nil
}

func (j *jwtIntrospection) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := log.FromContext(middlewares.GetLoggerCtx(req.Context(), j.name, basicTypeName))

	token, err := request.AuthorizationHeaderExtractor.ExtractToken(req)
	if err != nil {
		logger.Warning("Bearer token extraction failed")
		tracing.SetErrorWithEvent(req, "Bearer token extraction failed")
		return
	}

	c := http.Client{Timeout: time.Second * 10}

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", j.clientId)
	data.Set("client_secret", j.clientSecret)

	r, err := http.NewRequest("POST", j.endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		logger.Warning("Bearer token extraction failed")
		tracing.SetErrorWithEvent(req, "Bearer token extraction failed")
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := c.Do(r)
	if err != nil {
		logger.Warning("Oauth token introspection failed")
		tracing.SetErrorWithEvent(req, "Oauth token introspection failed")
		return
	}

	introspectionResp := struct {
		Active bool `json:"active"`
	}{}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Warning("Reading of Oauth token introspection response failed")
		tracing.SetErrorWithEvent(req, "Reading of Oauth token introspection response failed")
		return
	}

	err = json.Unmarshal(respBody, &introspectionResp)
	if err != nil {
		logger.Warning("Unmarshaling of Oauth token introspection response failed")
		tracing.SetErrorWithEvent(req, "Unmarshaling of Oauth token introspection response failed")
		return
	}

	if !introspectionResp.Active {
		logger.Debug("Authentication failed (token inactive)")
		tracing.SetErrorWithEvent(req, "Authentication failed (token inactive)")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte(`{"error": "unauthorized access"}`))
		return
	}

	j.next.ServeHTTP(rw, req)
}
