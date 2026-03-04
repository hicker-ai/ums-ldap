package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/qinzj/ums-ldap/pkg/logs"
)

// Config holds all configuration for the application.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	LDAP     LDAPConfig     `mapstructure:"ldap"`
	Log      LogConfig      `mapstructure:"log"`
	JWT      JWTConfig      `mapstructure:"jwt"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	HTTPPort int `mapstructure:"http_port"`
}

// DatabaseConfig holds database connection configuration.
type DatabaseConfig struct {
	Driver   string `mapstructure:"driver"`   // "sqlite3" | "postgres"
	Path     string `mapstructure:"path"`     // SQLite file path, e.g. "data/app.db"
	Host     string `mapstructure:"host"`     // PostgreSQL host
	Port     int    `mapstructure:"port"`     // PostgreSQL port
	User     string `mapstructure:"user"`     // PostgreSQL user
	Password string `mapstructure:"password"` // PostgreSQL password
	DBName   string `mapstructure:"dbname"`   // PostgreSQL database name
	SSLMode  string `mapstructure:"sslmode"`  // PostgreSQL SSL mode: "disable" | "require" | "verify-ca" | "verify-full"
}

// DSN returns the database connection string based on the configured driver.
func (d DatabaseConfig) DSN() string {
	switch d.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
	default: // sqlite3
		return fmt.Sprintf("file:%s?_fk=1", d.Path)
	}
}

// EnsureDataDir creates the directory for SQLite database file if needed.
func (d DatabaseConfig) EnsureDataDir() error {
	if d.Driver != "" && d.Driver != "sqlite3" {
		return nil
	}
	dir := filepath.Dir(d.Path)
	return os.MkdirAll(dir, 0755)
}

// LDAPConfig holds LDAP server configuration.
type LDAPConfig struct {
	Port   int    `mapstructure:"port"`    // LDAP server port
	BaseDN string `mapstructure:"base_dn"` // Base DN, e.g. "dc=example,dc=com"
	Mode   string `mapstructure:"mode"`    // "openldap" | "activedirectory"
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Console   bool         `mapstructure:"console"`    // enable console output
	AddSource bool         `mapstructure:"add_source"` // include caller info (file:line)
	Level     string       `mapstructure:"level"`      // "debug" | "info" | "warn" | "error" | "fatal"
	Format    string       `mapstructure:"format"`     // "text" | "json"
	Rotate    RotateConfig `mapstructure:"rotate"`     // file rotation config
}

// RotateConfig holds log file rotation configuration.
type RotateConfig struct {
	Enabled    bool   `mapstructure:"enabled"`     // enable file output
	OutputPath string `mapstructure:"output_path"` // log directory, e.g. "./logs"
	MaxSize    int    `mapstructure:"max_size"`    // max size per file in MB
	MaxAge     int    `mapstructure:"max_age"`     // max days to retain old files
	MaxBackups int    `mapstructure:"max_backups"` // max number of old files to retain
	Compress   bool   `mapstructure:"compress"`    // gzip old files
	LocalTime  bool   `mapstructure:"local_time"`  // use local time in filenames (default UTC)
}

// ToLogsConfig converts LogConfig to logs.Config.
func (l LogConfig) ToLogsConfig() logs.Config {
	return logs.Config{
		Console:   l.Console,
		AddSource: l.AddSource,
		Level:     l.Level,
		Format:    logs.Format(l.Format),
		Rotate: logs.OutFile{
			Enabled:    l.Rotate.Enabled,
			OutputPath: l.Rotate.OutputPath,
			MaxSize:    l.Rotate.MaxSize,
			MaxAge:     l.Rotate.MaxAge,
			MaxBackups: l.Rotate.MaxBackups,
			Compress:   l.Rotate.Compress,
			LocalTime:  l.Rotate.LocalTime,
		},
	}
}

// JWTConfig holds JWT authentication configuration.
type JWTConfig struct {
	Secret      string `mapstructure:"secret"`       // JWT signing secret, change in production
	ExpireHours int    `mapstructure:"expire_hours"` // token expiration in hours
}

// Load reads configuration from the specified YAML file.
func Load(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}
