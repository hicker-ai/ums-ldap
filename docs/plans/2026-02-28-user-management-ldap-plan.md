# User Management System with LDAP Server — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a user management system with dual-port HTTP+LDAP server, supporting user/group CRUD, LDAP search with RFC 4515 filter parsing, and Bind authentication, compatible with OpenLDAP and Microsoft AD conventions.

**Architecture:** Single Go binary running Gin HTTP (:8080) and gldap LDAP (:389) concurrently. Both handler layers share the same Service→DAO→PostgreSQL stack following Clean Architecture. LDAP filter strings are parsed into an AST then converted to Ent ORM predicates for database-level filtering.

**Tech Stack:** Go 1.22+, Gin, Ent ORM, Zap, gldap, go-ldap/ldap/v3 (filter parsing), PostgreSQL, Cobra CLI, React 18, Ant Design 5, Vite

**Design doc:** `docs/plans/2026-02-28-user-management-ldap-design.md`

**Rules:** Follow `.claude/rules/` and `.ai-context/rules/` (core principles, Go code style, project architecture, testing, security)

---

## Task 1: Project Scaffold & Go Module Init

**Files:**
- Create: `go.mod`, `go.sum`
- Create: `cmd/server/main.go`
- Create: `cmd/server/root.go`
- Create: `internal/config/config.go`
- Create: `configs/config.yaml`

**Step 1: Initialize Go module**

Run:
```bash
cd /Users/qinzj/github/claude-demo
go mod init github.com/qinzj/ums-ldap
```

**Step 2: Install core dependencies**

Run:
```bash
go get github.com/spf13/cobra@latest
go get github.com/spf13/viper@latest
go get github.com/gin-gonic/gin@latest
go get go.uber.org/zap@latest
go get entgo.io/ent@latest
go get github.com/lib/pq@latest
go get github.com/jimlambrt/gldap@latest
go get github.com/go-ldap/ldap/v3@latest
go get github.com/google/uuid@latest
go get golang.org/x/crypto@latest
```

**Step 3: Create config struct**

Create `internal/config/config.go`:
```go
package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	LDAP     LDAPConfig     `mapstructure:"ldap"`
	Log      LogConfig      `mapstructure:"log"`
}

type ServerConfig struct {
	HTTPPort int `mapstructure:"http_port"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

type LDAPConfig struct {
	Port   int    `mapstructure:"port"`
	BaseDN string `mapstructure:"base_dn"`
	Mode   string `mapstructure:"mode"` // "openldap" or "activedirectory"
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

func Load(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```

**Step 4: Create config file**

Create `configs/config.yaml`:
```yaml
server:
  http_port: 8080

database:
  host: localhost
  port: 5432
  user: postgres
  password: postgres
  dbname: usermanager
  sslmode: disable

ldap:
  port: 10389
  base_dn: "dc=example,dc=com"
  mode: "openldap"

log:
  level: "info"
```

**Step 5: Create Cobra CLI entry point**

Create `cmd/server/root.go`:
```go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "usermanager",
	Short: "User management system with LDAP server",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "configs/config.yaml", "config file path")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

Create `cmd/server/main.go`:
```go
package main

func main() {
	Execute()
}
```

**Step 6: Verify build**

Run: `go build ./cmd/server/`
Expected: Success, no errors

**Step 7: Commit**

```bash
git add go.mod go.sum cmd/ internal/config/ configs/
git commit -m "feat: project scaffold with Cobra CLI, config, and dependencies"
```

---

## Task 2: Ent Schema Definitions

**Files:**
- Create: `internal/schema/user.go`
- Create: `internal/schema/group.go`
- Generated: `internal/ent/` (by `go generate`)

**Step 1: Initialize Ent**

Run:
```bash
go run -mod=mod entgo.io/ent/cmd/ent new User Group
mv ent/schema/* internal/schema/
rm -rf ent/
```

**Step 2: Define User schema**

Create `internal/schema/user.go`:
```go
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Immutable(),
		field.String("username").Unique().NotEmpty().MaxLen(64),
		field.String("display_name").NotEmpty().MaxLen(128),
		field.String("email").Unique().NotEmpty().MaxLen(255),
		field.String("password_hash").Sensitive(),
		field.String("phone").Optional().MaxLen(32),
		field.Enum("status").Values("enabled", "disabled").Default("enabled"),
		field.Time("created_at").Immutable().Default(func() time.Time { return time.Now() }),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("groups", Group.Type).Ref("users"),
	}
}
```

**Step 3: Define Group schema**

Create `internal/schema/group.go`:
```go
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type Group struct {
	ent.Schema
}

func (Group) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Immutable(),
		field.String("name").Unique().NotEmpty().MaxLen(64),
		field.String("description").Optional().MaxLen(255),
		field.UUID("parent_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("created_at").Immutable().Default(func() time.Time { return time.Now() }),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (Group) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("users", User.Type),
		edge.To("children", Group.Type).From("parent").Field("parent_id").Unique(),
	}
}
```

**Step 4: Configure Ent generation**

Create `internal/ent/generate.go`:
```go
package ent

//go:generate go run -mod=mod entgo.io/ent/cmd/ent generate --target ./  ../schema
```

**Step 5: Generate Ent code**

Run:
```bash
cd internal/ent && go generate ./...
```
Expected: Generated files in `internal/ent/`

**Step 6: Verify compilation**

Run: `go build ./...`
Expected: Success

**Step 7: Commit**

```bash
git add internal/schema/ internal/ent/
git commit -m "feat: Ent schema for User and Group with many-to-many relation"
```

---

## Task 3: Domain Models & DAO Layer

**Files:**
- Create: `internal/domain/user.go`
- Create: `internal/domain/group.go`
- Create: `internal/dao/user.go`
- Create: `internal/dao/group.go`
- Create: `internal/dao/dao.go`

**Step 1: Create domain models**

Create `internal/domain/user.go`:
```go
package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserStatus string

const (
	UserStatusEnabled  UserStatus = "enabled"
	UserStatusDisabled UserStatus = "disabled"
)

type User struct {
	ID           uuid.UUID
	Username     string
	DisplayName  string
	Email        string
	PasswordHash string
	Phone        string
	Status       UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Groups       []*Group
}

type CreateUserInput struct {
	Username    string
	DisplayName string
	Email       string
	Password    string
	Phone       string
}

type UpdateUserInput struct {
	DisplayName *string
	Email       *string
	Phone       *string
}

type ListUsersInput struct {
	Page     int
	PageSize int
	Search   string
}

type ListResult[T any] struct {
	Items      []*T
	Total      int
	Page       int
	PageSize   int
}
```

Create `internal/domain/group.go`:
```go
package domain

import (
	"time"

	"github.com/google/uuid"
)

type Group struct {
	ID          uuid.UUID
	Name        string
	Description string
	ParentID    *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Children    []*Group
	Users       []*User
}

type CreateGroupInput struct {
	Name        string
	Description string
	ParentID    *uuid.UUID
}

type UpdateGroupInput struct {
	Name        *string
	Description *string
	ParentID    *uuid.UUID
}
```

**Step 2: Create DAO interface and implementation**

Create `internal/dao/dao.go`:
```go
package dao

import (
	"context"

	"github.com/qinzj/ums-ldap/internal/ent"
)

type DAO struct {
	client *ent.Client
}

func New(client *ent.Client) *DAO {
	return &DAO{client: client}
}

func (d *DAO) Client() *ent.Client {
	return d.client
}

func (d *DAO) AutoMigrate(ctx context.Context) error {
	return d.client.Schema.Create(ctx)
}
```

Create `internal/dao/user.go` — full CRUD operations with Ent queries, converting between Ent models and domain models.

Create `internal/dao/group.go` — full CRUD operations for groups including tree queries and membership management.

**Step 3: Write tests for DAO layer**

Create `internal/dao/user_test.go` and `internal/dao/group_test.go` with table-driven tests covering:
- Create user/group
- Get by ID
- List with pagination
- Update fields
- Delete
- Add/remove group members
- Query user's groups

Use SQLite in-memory for DAO tests (Ent supports dialect switching).

**Step 4: Run tests**

Run: `go test ./internal/dao/ -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/domain/ internal/dao/
git commit -m "feat: domain models and DAO layer with Ent queries"
```

---

## Task 4: Service Layer

**Files:**
- Create: `internal/service/user.go`
- Create: `internal/service/group.go`
- Create: `internal/service/auth.go`
- Create: `internal/service/user_test.go`
- Create: `internal/service/group_test.go`

**Step 1: Create UserService**

Create `internal/service/user.go`:
- `CreateUser(ctx, input)` — validate input, hash password with bcrypt, call DAO
- `GetUser(ctx, id)` — get user with groups eager-loaded
- `ListUsers(ctx, input)` — paginated list with search
- `UpdateUser(ctx, id, input)` — partial update
- `DeleteUser(ctx, id)` — soft or hard delete
- `ChangePassword(ctx, id, oldPw, newPw)` — verify old password, hash new
- `SetUserStatus(ctx, id, status)` — enable/disable
- `Authenticate(ctx, username, password)` — for LDAP Bind and HTTP login

**Step 2: Create GroupService**

Create `internal/service/group.go`:
- `CreateGroup(ctx, input)` — validate, check parent exists if provided
- `GetGroup(ctx, id)` — get group with users and children
- `ListGroups(ctx)` — return tree structure
- `UpdateGroup(ctx, id, input)` — validate no circular parent reference
- `DeleteGroup(ctx, id)` — check no child groups or members
- `AddMembers(ctx, groupID, userIDs)` — add users to group
- `RemoveMember(ctx, groupID, userID)` — remove user from group
- `GetGroupMembers(ctx, groupID)` — list members
- `GetUserGroups(ctx, userID)` — list user's groups

**Step 3: Create AuthService**

Create `internal/service/auth.go`:
- `Login(ctx, username, password)` — authenticate, return JWT token
- `ValidateToken(ctx, token)` — validate JWT, return user info

Use `golang.org/x/crypto/bcrypt` for password hashing. Use a simple JWT implementation or `github.com/golang-jwt/jwt/v5`.

**Step 4: Write service tests**

Table-driven tests with mocked DAO (or in-memory SQLite). Cover:
- Successful creation
- Duplicate username/email errors
- Password hashing verification
- Authentication success/failure
- Group hierarchy operations
- Membership operations

**Step 5: Run tests**

Run: `go test ./internal/service/ -v`
Expected: All PASS

**Step 6: Commit**

```bash
git add internal/service/
git commit -m "feat: service layer for user, group, and auth operations"
```

---

## Task 5: LDAP Filter Parser (RFC 4515)

This is the most critical module. Must be implemented with full test coverage.

**Files:**
- Create: `internal/ldap/filter/parser.go`
- Create: `internal/ldap/filter/ast.go`
- Create: `internal/ldap/filter/evaluator.go`
- Create: `internal/ldap/filter/parser_test.go`
- Create: `internal/ldap/filter/evaluator_test.go`

**Step 1: Define the filter AST**

Create `internal/ldap/filter/ast.go`:
```go
package filter

type FilterType int

const (
	FilterAnd FilterType = iota
	FilterOr
	FilterNot
	FilterEqual
	FilterSubstring
	FilterGreaterOrEqual
	FilterLessOrEqual
	FilterPresent
	FilterApproxMatch
)

type Filter struct {
	Type     FilterType
	Attr     string          // attribute name for leaf filters
	Value    string          // value for equal/gte/lte/approx
	Children []*Filter       // sub-filters for AND/OR/NOT
	Substr   *SubstringFilter // for substring match
}

type SubstringFilter struct {
	Initial string   // prefix before first *
	Any     []string // middle parts between *s
	Final   string   // suffix after last *
}
```

**Step 2: Write failing parser tests**

Create `internal/ldap/filter/parser_test.go` with table-driven tests:
```go
func TestParse(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   *Filter
		errMsg string
	}{
		{"equal", "(cn=John)", &Filter{Type: FilterEqual, Attr: "cn", Value: "John"}, ""},
		{"presence", "(cn=*)", &Filter{Type: FilterPresent, Attr: "cn"}, ""},
		{"substring_prefix", "(cn=Jo*)", &Filter{Type: FilterSubstring, Attr: "cn", Substr: &SubstringFilter{Initial: "Jo"}}, ""},
		{"substring_any", "(cn=*oh*)", &Filter{Type: FilterSubstring, Attr: "cn", Substr: &SubstringFilter{Any: []string{"oh"}}}, ""},
		{"substring_final", "(cn=*ohn)", &Filter{Type: FilterSubstring, Attr: "cn", Substr: &SubstringFilter{Final: "ohn"}}, ""},
		{"substring_complex", "(cn=J*o*hn)", &Filter{Type: FilterSubstring, Attr: "cn", Substr: &SubstringFilter{Initial: "J", Any: []string{"o"}, Final: "hn"}}, ""},
		{"gte", "(age>=18)", &Filter{Type: FilterGreaterOrEqual, Attr: "age", Value: "18"}, ""},
		{"lte", "(age<=65)", &Filter{Type: FilterLessOrEqual, Attr: "age", Value: "65"}, ""},
		{"approx", "(cn~=Jon)", &Filter{Type: FilterApproxMatch, Attr: "cn", Value: "Jon"}, ""},
		{"and", "(&(cn=John)(mail=j@e.com))", &Filter{Type: FilterAnd, Children: []*Filter{{Type: FilterEqual, Attr: "cn", Value: "John"}, {Type: FilterEqual, Attr: "mail", Value: "j@e.com"}}}, ""},
		{"or", "(|(cn=John)(cn=Jane))", &Filter{Type: FilterOr, Children: []*Filter{{Type: FilterEqual, Attr: "cn", Value: "John"}, {Type: FilterEqual, Attr: "cn", Value: "Jane"}}}, ""},
		{"not", "(!(cn=John))", &Filter{Type: FilterNot, Children: []*Filter{{Type: FilterEqual, Attr: "cn", Value: "John"}}}, ""},
		{"nested", "(&(|(cn=John)(cn=Jane))(mail=*@example.com))", nil, ""}, // verify structure
		{"escaped_chars", "(cn=John\\2a\\28Doe\\29)", &Filter{Type: FilterEqual, Attr: "cn", Value: "John*(Doe)"}, ""},
		{"empty_filter", "", nil, "empty filter"},
		{"unbalanced_parens", "(cn=John", nil, "unexpected end"},
		{"objectclass", "(objectClass=inetOrgPerson)", &Filter{Type: FilterEqual, Attr: "objectClass", Value: "inetOrgPerson"}, ""},
	}
	// ...
}
```

**Step 3: Run tests to verify they fail**

Run: `go test ./internal/ldap/filter/ -v -run TestParse`
Expected: FAIL — package does not compile yet

**Step 4: Implement the parser**

Create `internal/ldap/filter/parser.go`:
- Use `github.com/go-ldap/ldap/v3`'s `CompileFilter` to parse the filter string into a BER packet
- Walk the BER packet tree to build our `Filter` AST
- Handle all filter types: AND, OR, NOT, Equal, Substring, GTE, LTE, Present, ApproxMatch
- Handle LDAP escape sequences (`\2a` → `*`, `\28` → `(`, `\29` → `)`, `\5c` → `\`, `\00` → NUL)
- Return descriptive errors for malformed filters

**Step 5: Run parser tests**

Run: `go test ./internal/ldap/filter/ -v -run TestParse`
Expected: All PASS

**Step 6: Write failing evaluator tests**

Create `internal/ldap/filter/evaluator_test.go`:
- Test converting Filter AST to Ent predicates
- Test each filter type individually
- Test nested compound filters
- Test with mock attribute mapping (OpenLDAP and AD modes)

**Step 7: Implement evaluator**

Create `internal/ldap/filter/evaluator.go`:
```go
package filter

import (
	"entgo.io/ent/dialect/sql"
)

type AttrMapper interface {
	MapAttribute(ldapAttr string) (dbColumn string, ok bool)
}

type Evaluator struct {
	mapper AttrMapper
}

func NewEvaluator(mapper AttrMapper) *Evaluator {
	return &Evaluator{mapper: mapper}
}

// ToPredicate converts a Filter AST to an Ent SQL predicate.
func (e *Evaluator) ToPredicate(f *Filter) (*sql.Predicate, error) {
	// Recursively build predicates:
	// FilterEqual     → P().EQ(col, val)
	// FilterPresent   → P().Not().IsNull(col)
	// FilterSubstring → P().Contains(col, val) / HasPrefix / HasSuffix / LIKE
	// FilterGTE       → P().GTE(col, val)
	// FilterLTE       → P().LTE(col, val)
	// FilterApprox    → case-insensitive EqualFold
	// FilterAnd       → P().And(children...)
	// FilterOr        → P().Or(children...)
	// FilterNot       → P().Not().And(child)
}
```

**Step 8: Run evaluator tests**

Run: `go test ./internal/ldap/filter/ -v`
Expected: All PASS

**Step 9: Commit**

```bash
git add internal/ldap/filter/
git commit -m "feat: RFC 4515 LDAP filter parser and Ent predicate evaluator"
```

---

## Task 6: LDAP DN Module & Attribute Mapping

**Files:**
- Create: `internal/ldap/dn/dn.go`
- Create: `internal/ldap/dn/dn_test.go`
- Create: `internal/ldap/attrs/mapper.go`
- Create: `internal/ldap/attrs/mapper_test.go`

**Step 1: Write failing DN tests**

Test cases:
- Build user DN from username and base DN (OpenLDAP: `uid=john,ou=users,dc=example,dc=com`)
- Build user DN for AD mode (`cn=John,cn=Users,dc=example,dc=com`)
- Build group DN from group name and hierarchy
- Parse DN to extract components
- Validate DN format

**Step 2: Implement DN module**

`internal/ldap/dn/dn.go`:
- `BuildUserDN(username, displayName, baseDN, mode)` — build DN based on mode
- `BuildGroupDN(groupName, baseDN, mode)` — build group DN
- `ParseDN(dn)` — parse DN into components (RDN list)
- `ExtractUsername(dn, mode)` — extract username from user DN

**Step 3: Run DN tests**

Run: `go test ./internal/ldap/dn/ -v`
Expected: All PASS

**Step 4: Write failing attribute mapper tests**

Test cases:
- OpenLDAP mode: `uid` → `username`, `cn` → `display_name`, `mail` → `email`
- AD mode: `sAMAccountName` → `username`, `cn` → `display_name`
- Unknown attribute returns `("", false)`
- `objectClass` returns appropriate values per mode

**Step 5: Implement attribute mapper**

`internal/ldap/attrs/mapper.go`:
```go
package attrs

type Mode string

const (
	ModeOpenLDAP        Mode = "openldap"
	ModeActiveDirectory Mode = "activedirectory"
)

type Mapper struct {
	mode Mode
}

func NewMapper(mode Mode) *Mapper { return &Mapper{mode: mode} }

func (m *Mapper) MapAttribute(ldapAttr string) (dbColumn string, ok bool) {
	// mode-aware mapping
}

func (m *Mapper) UserObjectClasses() []string {
	// OpenLDAP: ["inetOrgPerson", "organizationalPerson", "person", "top"]
	// AD: ["user", "person", "organizationalPerson", "top"]
}

func (m *Mapper) GroupObjectClasses() []string {
	// OpenLDAP: ["groupOfNames", "top"]
	// AD: ["group", "top"]
}

func (m *Mapper) UserToLDAPAttrs(user *domain.User) map[string][]string {
	// Convert domain User to LDAP attribute map based on mode
}

func (m *Mapper) GroupToLDAPAttrs(group *domain.Group, memberDNs []string) map[string][]string {
	// Convert domain Group to LDAP attribute map based on mode
}
```

**Step 6: Run attribute mapper tests**

Run: `go test ./internal/ldap/attrs/ -v`
Expected: All PASS

**Step 7: Commit**

```bash
git add internal/ldap/dn/ internal/ldap/attrs/
git commit -m "feat: LDAP DN builder/parser and attribute mapper for OpenLDAP/AD"
```

---

## Task 7: LDAP Handler (Bind & Search)

**Files:**
- Create: `internal/handler/ldap/handler.go`
- Create: `internal/handler/ldap/bind.go`
- Create: `internal/handler/ldap/search.go`
- Create: `internal/handler/ldap/handler_test.go`

**Step 1: Create LDAP handler struct**

`internal/handler/ldap/handler.go`:
```go
package ldap

import (
	"github.com/jimlambrt/gldap"
	"go.uber.org/zap"
)

type Handler struct {
	userService  UserService
	groupService GroupService
	authService  AuthService
	mapper       *attrs.Mapper
	dnBuilder    *dn.Builder
	baseDN       string
	logger       *zap.Logger
}

// Interfaces defined in consuming layer (per project rules)
type UserService interface {
	Authenticate(ctx context.Context, username, password string) (*domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	SearchUsers(ctx context.Context, predicate ...) ([]*domain.User, error)
}

type GroupService interface {
	SearchGroups(ctx context.Context, predicate ...) ([]*domain.Group, error)
	GetGroupMembers(ctx context.Context, groupID uuid.UUID) ([]*domain.User, error)
}

func (h *Handler) RegisterRoutes(mux *gldap.Mux) {
	mux.Bind(h.handleBind)
	mux.Search(h.handleSearch)
}
```

**Step 2: Implement Bind handler**

`internal/handler/ldap/bind.go`:
- Parse DN from bind request to extract username
- Call `AuthService.Authenticate(username, password)`
- Return `ResultSuccess` or `ResultInvalidCredentials`
- Log bind attempts (success/failure) with Zap

**Step 3: Implement Search handler**

`internal/handler/ldap/search.go`:
- Parse the search filter string using `filter.Parse()`
- Determine search target (users or groups) based on baseDN and filter objectClass
- Convert filter AST to Ent predicates using `filter.Evaluator`
- Apply scope (BaseObject, SingleLevel, WholeSubtree)
- Query service layer
- Convert results to LDAP entries using attribute mapper
- Write entries to response writer
- Handle sizeLimit and timeLimit from search request

**Step 4: Write integration tests**

`internal/handler/ldap/handler_test.go`:
- Use `gldap`'s test utilities or `go-ldap/ldap/v3` client to connect
- Test Bind with valid/invalid credentials
- Test Search with various filters:
  - `(objectClass=inetOrgPerson)` — all users
  - `(uid=john)` — specific user
  - `(&(objectClass=inetOrgPerson)(mail=*@example.com))` — compound filter
  - `(objectClass=groupOfNames)` — all groups
  - `(|(cn=admin)(cn=users))` — OR filter on groups
  - `(!(status=disabled))` — NOT filter
  - `(cn=J*)` — substring filter
- Test scope handling
- Test attribute selection (return only requested attributes)

**Step 5: Run tests**

Run: `go test ./internal/handler/ldap/ -v`
Expected: All PASS

**Step 6: Commit**

```bash
git add internal/handler/ldap/
git commit -m "feat: LDAP Bind and Search handlers with gldap"
```

---

## Task 8: HTTP Handlers

**Files:**
- Create: `internal/handler/http/user.go`
- Create: `internal/handler/http/group.go`
- Create: `internal/handler/http/auth.go`
- Create: `internal/handler/http/ldap_config.go`
- Create: `internal/handler/http/router.go`
- Create: `internal/handler/http/response.go`
- Create: `internal/middleware/auth.go`
- Create: `internal/middleware/logger.go`

**Step 1: Create response helpers**

`internal/handler/http/response.go`:
```go
package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func OK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{Code: 0, Message: "success", Data: data})
}

func Error(c *gin.Context, httpStatus int, msg string) {
	c.JSON(httpStatus, Response{Code: -1, Message: msg})
}
```

**Step 2: Create router setup**

`internal/handler/http/router.go`:
- Register all routes under `/api/v1/`
- Apply auth middleware to protected routes
- Apply logging middleware globally

**Step 3: Implement user handlers**

`internal/handler/http/user.go`:
- Request DTOs with `json` and `binding` tags (per code style rules)
- `CreateUser`, `GetUser`, `ListUsers`, `UpdateUser`, `DeleteUser`, `ChangePassword`, `SetUserStatus`

**Step 4: Implement group handlers**

`internal/handler/http/group.go`:
- `CreateGroup`, `GetGroup`, `ListGroups`, `UpdateGroup`, `DeleteGroup`
- `AddMembers`, `RemoveMember`, `GetGroupMembers`, `GetUserGroups`

**Step 5: Implement auth handlers**

`internal/handler/http/auth.go`:
- `Login` — validate credentials, return JWT
- `Logout` — invalidate token (if stateful) or no-op (if stateless JWT)

**Step 6: Implement middleware**

`internal/middleware/auth.go`:
- Extract JWT from Authorization header
- Validate token
- Set user info in Gin context

`internal/middleware/logger.go`:
- Log request/response with Zap (structured logging per rules)

**Step 7: Write handler tests**

Use `httptest` and Gin's test mode. Table-driven tests for each endpoint. Cover:
- Successful operations
- Validation errors (missing required fields)
- Not found errors
- Duplicate key errors

**Step 8: Run tests**

Run: `go test ./internal/handler/http/ -v`
Expected: All PASS

**Step 9: Commit**

```bash
git add internal/handler/http/ internal/middleware/
git commit -m "feat: HTTP REST API handlers for users, groups, auth"
```

---

## Task 9: Server Startup (Dual-Port)

**Files:**
- Modify: `cmd/server/root.go`
- Create: `cmd/server/serve.go`

**Step 1: Create serve command**

`cmd/server/serve.go`:
```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jimlambrt/gldap"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	// ... internal imports
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP and LDAP servers",
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	// ... error handling

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Init DB (Ent client)
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User,
		cfg.Database.Password, cfg.Database.DBName, cfg.Database.SSLMode)
	entClient, err := ent.Open("postgres", dsn)
	// ... error handling, auto-migrate

	// Init layers
	daoLayer := dao.New(entClient)
	userSvc := service.NewUserService(daoLayer)
	groupSvc := service.NewGroupService(daoLayer)
	authSvc := service.NewAuthService(daoLayer)

	// Start HTTP server
	router := http.SetupRouter(userSvc, groupSvc, authSvc, logger)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler: router,
	}
	go httpServer.ListenAndServe()
	logger.Info("HTTP server started", zap.Int("port", cfg.Server.HTTPPort))

	// Start LDAP server
	ldapHandler := ldaphandler.New(userSvc, groupSvc, authSvc, cfg.LDAP, logger)
	ldapServer, _ := gldap.NewServer()
	mux, _ := gldap.NewMux()
	ldapHandler.RegisterRoutes(mux)
	ldapServer.Router(mux)
	go ldapServer.Run(fmt.Sprintf(":%d", cfg.LDAP.Port))
	logger.Info("LDAP server started", zap.Int("port", cfg.LDAP.Port))

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down...")
	httpServer.Shutdown(context.Background())
	ldapServer.Stop()
	entClient.Close()
	return nil
}
```

**Step 2: Verify build and manual startup test**

Run: `go build -o bin/usermanager ./cmd/server/`
Expected: Binary builds successfully

**Step 3: Commit**

```bash
git add cmd/server/
git commit -m "feat: dual-port server startup with graceful shutdown"
```

---

## Task 10: Frontend — Project Setup & Login Page

**Files:**
- Create: `web/package.json` and project files via Vite
- Create: `web/src/pages/Login.tsx`
- Create: `web/src/api/client.ts`
- Create: `web/src/api/auth.ts`

**Step 1: Initialize React project**

Run:
```bash
cd /Users/qinzj/github/claude-demo
npm create vite@latest web -- --template react-ts
cd web
npm install
npm install antd @ant-design/icons axios react-router-dom
```

**Step 2: Set up API client**

`web/src/api/client.ts`:
- Axios instance with base URL `/api/v1`
- Request interceptor to attach JWT token
- Response interceptor for error handling

**Step 3: Create auth API**

`web/src/api/auth.ts`:
- `login(username, password)` → POST `/auth/login`
- `logout()` → POST `/auth/logout`

**Step 4: Create Login page**

`web/src/pages/Login.tsx`:
- Ant Design Form with username/password fields
- Submit → call auth API → store token → redirect to user list

**Step 5: Set up routing**

`web/src/App.tsx`:
- React Router with login/dashboard routes
- Auth guard for protected routes

**Step 6: Verify frontend runs**

Run: `cd web && npm run dev`
Expected: Dev server starts, login page renders

**Step 7: Commit**

```bash
git add web/
git commit -m "feat: frontend project setup with login page"
```

---

## Task 11: Frontend — User Management Pages

**Files:**
- Create: `web/src/pages/UserList.tsx`
- Create: `web/src/pages/UserDetail.tsx`
- Create: `web/src/api/users.ts`
- Create: `web/src/components/Layout.tsx`

**Step 1: Create layout component**

`web/src/components/Layout.tsx`:
- Ant Design ProLayout with sidebar navigation
- Menu items: Users, Groups, LDAP Config
- Header with user info and logout

**Step 2: Create user API**

`web/src/api/users.ts`:
- `listUsers(params)`, `getUser(id)`, `createUser(data)`, `updateUser(id, data)`, `deleteUser(id)`
- `changePassword(id, data)`, `setUserStatus(id, status)`
- `getUserGroups(id)`

**Step 3: Create UserList page**

`web/src/pages/UserList.tsx`:
- Ant Design Table with pagination
- Search input for filtering
- Create button → modal with form
- Row actions: edit, enable/disable, delete (with confirm)
- Status tag (green=enabled, red=disabled)

**Step 4: Create UserDetail page**

`web/src/pages/UserDetail.tsx`:
- User info form (editable)
- Password change section
- Group membership list with add/remove

**Step 5: Verify pages render correctly**

Run: `cd web && npm run dev`
Expected: Pages render, table loads (may need mock data or running backend)

**Step 6: Commit**

```bash
git add web/src/
git commit -m "feat: user list and detail pages with Ant Design"
```

---

## Task 12: Frontend — Group Management Pages

**Files:**
- Create: `web/src/pages/GroupList.tsx`
- Create: `web/src/pages/GroupDetail.tsx`
- Create: `web/src/api/groups.ts`

**Step 1: Create group API**

`web/src/api/groups.ts`:
- `listGroups()`, `getGroup(id)`, `createGroup(data)`, `updateGroup(id, data)`, `deleteGroup(id)`
- `getGroupMembers(id)`, `addMembers(id, userIds)`, `removeMember(id, userId)`

**Step 2: Create GroupList page**

`web/src/pages/GroupList.tsx`:
- Ant Design Tree component showing group hierarchy
- Create group button → modal with form (name, description, parent selector)
- Click node → navigate to group detail

**Step 3: Create GroupDetail page**

`web/src/pages/GroupDetail.tsx`:
- Group info form
- Member list (Ant Design Table)
- Add member button → modal with user search/select (Ant Design Transfer or Select)
- Remove member action

**Step 4: Verify**

Run: `cd web && npm run dev`
Expected: Group pages render correctly

**Step 5: Commit**

```bash
git add web/src/
git commit -m "feat: group list and detail pages with tree structure"
```

---

## Task 13: Frontend — LDAP Config Page

**Files:**
- Create: `web/src/pages/LDAPConfig.tsx`
- Create: `web/src/api/ldap.ts`

**Step 1: Create LDAP API**

`web/src/api/ldap.ts`:
- `getConfig()`, `updateConfig(data)`, `getStatus()`

**Step 2: Create LDAP Config page**

`web/src/pages/LDAPConfig.tsx`:
- Form fields: Base DN, Mode (OpenLDAP/AD radio), Port
- LDAP service status card (running/stopped, connection count)
- Save button

**Step 3: Commit**

```bash
git add web/src/
git commit -m "feat: LDAP configuration page"
```

---

## Task 14: Integration Testing & Final Verification

**Files:**
- Create: `tests/integration/ldap_test.go`
- Create: `tests/integration/api_test.go`

**Step 1: Write LDAP integration tests**

Using `go-ldap/ldap/v3` client:
- Start test server (HTTP + LDAP) with SQLite
- Create users/groups via HTTP API
- Bind via LDAP with created user credentials
- Search with various filters and verify results
- Test OpenLDAP and AD mode switching
- Test all filter types in combination

**Step 2: Write HTTP API integration tests**

- Full user lifecycle (create → get → update → delete)
- Full group lifecycle with membership
- Auth flow (login → access protected endpoint → logout)

**Step 3: Run all tests**

Run: `go test ./... -v`
Expected: All PASS

**Step 4: Build and verify final binary**

Run:
```bash
go build -o bin/usermanager ./cmd/server/
./bin/usermanager serve --config configs/config.yaml
```
Expected: Both HTTP and LDAP servers start

**Step 5: Final commit**

```bash
git add tests/
git commit -m "feat: integration tests for LDAP and HTTP API"
```

---

## Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | Project scaffold | `cmd/server/`, `internal/config/`, `configs/` |
| 2 | Ent schemas | `internal/schema/`, `internal/ent/` |
| 3 | Domain & DAO | `internal/domain/`, `internal/dao/` |
| 4 | Service layer | `internal/service/` |
| 5 | LDAP filter parser | `internal/ldap/filter/` |
| 6 | LDAP DN & attrs | `internal/ldap/dn/`, `internal/ldap/attrs/` |
| 7 | LDAP handlers | `internal/handler/ldap/` |
| 8 | HTTP handlers | `internal/handler/http/`, `internal/middleware/` |
| 9 | Server startup | `cmd/server/serve.go` |
| 10 | Frontend: setup + login | `web/` |
| 11 | Frontend: users | `web/src/pages/User*.tsx` |
| 12 | Frontend: groups | `web/src/pages/Group*.tsx` |
| 13 | Frontend: LDAP config | `web/src/pages/LDAPConfig.tsx` |
| 14 | Integration tests | `tests/integration/` |
