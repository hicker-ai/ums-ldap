package service

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/qinzj/ums-ldap/internal/dao"
	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/ent/enttest"
)

func setupUserService(t *testing.T) (*UserService, context.Context) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	t.Cleanup(func() { client.Close() })
	d := dao.New(client)
	ctx := context.Background()
	if err := d.AutoMigrate(ctx); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return NewUserService(d), ctx
}

func TestUserServiceCreateUser(t *testing.T) {
	svc, ctx := setupUserService(t)

	u, err := svc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "john",
		DisplayName: "John Doe",
		Email:       "john@example.com",
		Password:    "password123",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Username != "john" {
		t.Errorf("Username = %q, want %q", u.Username, "john")
	}
	if u.PasswordHash == "password123" {
		t.Error("PasswordHash should be hashed, not plaintext")
	}
}

func TestUserServiceAuthenticate(t *testing.T) {
	svc, ctx := setupUserService(t)

	svc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "john",
		DisplayName: "John Doe",
		Email:       "john@example.com",
		Password:    "password123",
	})

	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{"valid credentials", "john", "password123", false},
		{"wrong password", "john", "wrongpassword", true},
		{"unknown user", "unknown", "password123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Authenticate(ctx, tt.username, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUserServiceAuthenticateDisabled(t *testing.T) {
	svc, ctx := setupUserService(t)

	u, _ := svc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "john",
		DisplayName: "John Doe",
		Email:       "john@example.com",
		Password:    "password123",
	})

	svc.SetUserStatus(ctx, u.ID, domain.UserStatusDisabled)

	_, err := svc.Authenticate(ctx, "john", "password123")
	if err == nil {
		t.Error("expected error authenticating disabled user")
	}
}

func TestUserServiceChangePassword(t *testing.T) {
	svc, ctx := setupUserService(t)

	u, _ := svc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "john",
		DisplayName: "John Doe",
		Email:       "john@example.com",
		Password:    "oldpassword",
	})

	if err := svc.ChangePassword(ctx, u.ID, "oldpassword", "newpassword"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// old password should no longer work
	_, err := svc.Authenticate(ctx, "john", "oldpassword")
	if err == nil {
		t.Error("expected error with old password after change")
	}

	// new password should work
	_, err = svc.Authenticate(ctx, "john", "newpassword")
	if err != nil {
		t.Errorf("new password should work: %v", err)
	}
}

func TestUserServiceChangePasswordWrongOld(t *testing.T) {
	svc, ctx := setupUserService(t)

	u, _ := svc.CreateUser(ctx, domain.CreateUserInput{
		Username:    "john",
		DisplayName: "John Doe",
		Email:       "john@example.com",
		Password:    "password123",
	})

	err := svc.ChangePassword(ctx, u.ID, "wrongold", "newpassword")
	if err == nil {
		t.Error("expected error with wrong old password")
	}
}

func TestUserServiceListUsers(t *testing.T) {
	svc, ctx := setupUserService(t)

	for i := 0; i < 5; i++ {
		name := "user" + string(rune('a'+i))
		svc.CreateUser(ctx, domain.CreateUserInput{
			Username:    name,
			DisplayName: "User " + name,
			Email:       name + "@example.com",
			Password:    "password",
		})
	}

	result, err := svc.ListUsers(ctx, domain.ListUsersInput{Page: 1, PageSize: 3})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if result.Total != 5 {
		t.Errorf("Total = %d, want 5", result.Total)
	}
	if len(result.Items) != 3 {
		t.Errorf("Items = %d, want 3", len(result.Items))
	}
}
