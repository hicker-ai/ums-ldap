package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"

	"github.com/qinzj/ums-ldap/internal/config"
	"github.com/qinzj/ums-ldap/internal/dao"
	"github.com/qinzj/ums-ldap/internal/ent"
	httphandler "github.com/qinzj/ums-ldap/internal/handler/http"
	ldaphandler "github.com/qinzj/ums-ldap/internal/handler/ldap"
	"github.com/qinzj/ums-ldap/internal/service"
)

var (
	httpServer  *httptest.Server
	ldapAddr    string
	ldapServer  *gldap.Server
	userSvc     *service.UserService
	groupSvc    *service.GroupService
	authSvc     *service.AuthService
	testBaseDN  = "dc=example,dc=com"
	testMode    = "openldap"
	jwtSecret   = "test-secret-key"
	expireHours = 24
)

func TestMain(m *testing.M) {
	// Init logger
	logger, _ := zap.NewDevelopment()

	// Init Ent client with SQLite in-memory (bypass enttest since no *testing.T)
	client, err := ent.Open("sqlite3", "file:ent?mode=memory&_fk=1")
	if err != nil {
		fmt.Fprintf(os.Stderr, "open ent client: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	d := dao.New(client)
	ctx := context.Background()
	if err := d.AutoMigrate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "auto migrate: %v\n", err)
		os.Exit(1)
	}

	// Init services
	userSvc = service.NewUserService(d)
	groupSvc = service.NewGroupService(d)
	authSvc = service.NewAuthService(userSvc, jwtSecret, expireHours)

	// Setup HTTP server
	ldapCfg := &config.LDAPConfig{
		Port:   0,
		BaseDN: testBaseDN,
		Mode:   testMode,
	}
	router := httphandler.SetupRouter(userSvc, groupSvc, authSvc, ldapCfg, logger)
	httpServer = httptest.NewServer(router)
	defer httpServer.Close()

	// Setup LDAP server
	ldapHandler := ldaphandler.New(userSvc, groupSvc, ldapCfg, logger)
	ldapServer, err = gldap.NewServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "create LDAP server: %v\n", err)
		os.Exit(1)
	}

	mux, err := gldap.NewMux()
	if err != nil {
		fmt.Fprintf(os.Stderr, "create LDAP mux: %v\n", err)
		os.Exit(1)
	}
	ldapHandler.RegisterRoutes(mux)
	ldapServer.Router(mux)

	// Find free port for LDAP
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	ldapAddr = listener.Addr().String()
	_ = listener.Close()

	go func() {
		if err := ldapServer.Run(ldapAddr); err != nil {
			fmt.Fprintf(os.Stderr, "LDAP server: %v\n", err)
		}
	}()

	// Wait for LDAP server to start
	time.Sleep(200 * time.Millisecond)

	code := m.Run()

	_ = ldapServer.Stop()
	os.Exit(code)
}

// apiResponse is the standard API response envelope.
type apiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// doAPI sends a JSON request and returns the response.
func doAPI(t *testing.T, method, path string, body interface{}, token string) *http.Response {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}

	req, err := http.NewRequest(method, httpServer.URL+path, &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// parseResponse reads the body and returns the parsed API response.
func parseResponse(t *testing.T, resp *http.Response) apiResponse {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	var r apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return r
}

// loginAndGetToken logs in and returns the JWT token.
func loginAndGetToken(t *testing.T, username, password string) string {
	t.Helper()

	resp := doAPI(t, "POST", "/api/v1/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, "")
	r := parseResponse(t, resp)
	if r.Code != 0 {
		t.Fatalf("login failed: %s", r.Message)
	}

	var data struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(r.Data, &data); err != nil {
		t.Fatalf("unmarshal login data: %v", err)
	}
	return data.Token
}

// createUserViaAPI creates a user through the HTTP API.
func createUserViaAPI(t *testing.T, token string, req map[string]string) string {
	t.Helper()
	resp := doAPI(t, "POST", "/api/v1/users", req, token)
	r := parseResponse(t, resp)
	if r.Code != 0 {
		t.Fatalf("create user failed: %s", r.Message)
	}
	var data struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(r.Data, &data); err != nil {
		t.Fatalf("unmarshal user: %v", err)
	}
	return data.ID
}

// createGroupViaAPI creates a group through the HTTP API.
func createGroupViaAPI(t *testing.T, token string, req map[string]interface{}) string {
	t.Helper()
	resp := doAPI(t, "POST", "/api/v1/groups", req, token)
	r := parseResponse(t, resp)
	if r.Code != 0 {
		t.Fatalf("create group failed: %s", r.Message)
	}
	var data struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(r.Data, &data); err != nil {
		t.Fatalf("unmarshal group: %v", err)
	}
	return data.ID
}
