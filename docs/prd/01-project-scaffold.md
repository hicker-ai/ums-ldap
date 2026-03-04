# PRD-01: 项目脚手架

## 目标

初始化 Go Module，安装所有依赖，创建 Cobra CLI 入口和配置加载模块。

## 交付物

- `go.mod` / `go.sum`
- `cmd/server/main.go` — 程序入口
- `cmd/server/root.go` — Cobra root command
- `internal/config/config.go` — 配置结构体与加载逻辑
- `configs/config.yaml` — 默认配置文件

## 详细要求

### 1. Go Module 初始化

```bash
go mod init github.com/qinzj/ums-ldap
```

### 2. 依赖安装

```
github.com/spf13/cobra
github.com/spf13/viper
github.com/gin-gonic/gin
go.uber.org/zap
entgo.io/ent
github.com/lib/pq
github.com/jimlambrt/gldap
github.com/go-ldap/ldap/v3
github.com/google/uuid
golang.org/x/crypto
github.com/golang-jwt/jwt/v5
```

### 3. 配置结构体

```go
type Config struct {
    Server   ServerConfig   // http_port
    Database DatabaseConfig // host, port, user, password, dbname, sslmode
    LDAP     LDAPConfig     // port, base_dn, mode (openldap/activedirectory)
    Log      LogConfig      // level
}
```

使用 Viper 加载 YAML 配置文件。

### 4. 默认配置

- HTTP port: 8080
- DB: localhost:5432/usermanager
- LDAP port: 10389, base_dn: dc=example,dc=com, mode: openldap
- Log level: info

### 5. Cobra CLI

- Root command: `usermanager`
- Flag: `--config` 指定配置文件路径，默认 `configs/config.yaml`

## 验收标准

- `go build ./cmd/server/` 编译成功
- `./usermanager --help` 显示帮助信息
- 配置加载测试通过
