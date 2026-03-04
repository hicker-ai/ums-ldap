package service

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/qinzj/ums-ldap/internal/dao"
	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/ent/enttest"
)

func setupAuthService(t *testing.T) (*AuthService, *UserService, context.Context) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	t.Cleanup(func() { client.Close() })
	d := dao.New(client)
	ctx := context.Background()
	if err := d.AutoMigrate(ctx); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	userSvc := NewUserService(d)
	authSvc := NewAuthService(userSvc, "test-secret", 24)
	return authSvc, userSvc, ctx
}

func TestAuthServiceLogin(t *testing.T) {
	authSvc, userSvc, ctx := setupAuthService(t)

	userSvc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "admin",
		DisplayName: "Admin",
		Email:       "admin@example.com",
		Password:    "adminpass",
	})

	token, u, err := authSvc.Login(ctx, "admin", "adminpass")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
	if u.Username != "admin" {
		t.Errorf("Username = %q, want %q", u.Username, "admin")
	}
}

func TestAuthServiceLoginInvalidCredentials(t *testing.T) {
	authSvc, userSvc, ctx := setupAuthService(t)

	userSvc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "admin",
		DisplayName: "Admin",
		Email:       "admin@example.com",
		Password:    "adminpass",
	})

	_, _, err := authSvc.Login(ctx, "admin", "wrongpass")
	if err == nil {
		t.Error("expected error for invalid credentials")
	}
}

func TestAuthServiceValidateToken(t *testing.T) {
	authSvc, userSvc, ctx := setupAuthService(t)

	userSvc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "admin",
		DisplayName: "Admin",
		Email:       "admin@example.com",
		Password:    "adminpass",
	})

	token, _, _ := authSvc.Login(ctx, "admin", "adminpass")

	claims, err := authSvc.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Username != "admin" {
		t.Errorf("Username = %q, want %q", claims.Username, "admin")
	}
}

func TestAuthServiceValidateInvalidToken(t *testing.T) {
	authSvc, _, ctx := setupAuthService(t)

	_, err := authSvc.ValidateToken(ctx, "invalid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}
