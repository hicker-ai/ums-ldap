package dao

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/ent/enttest"
)

func setupTestDAO(t *testing.T) (*DAO, context.Context) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	t.Cleanup(func() { client.Close() })
	d := New(client)
	ctx := context.Background()
	if err := d.AutoMigrate(ctx); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return d, ctx
}

func TestCreateUser(t *testing.T) {
	d, ctx := setupTestDAO(t)

	u, err := d.CreateUser(ctx, "john", "John Doe", "john@example.com", "hashedpw", "1234567890")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Username != "john" {
		t.Errorf("Username = %q, want %q", u.Username, "john")
	}
	if u.DisplayName != "John Doe" {
		t.Errorf("DisplayName = %q, want %q", u.DisplayName, "John Doe")
	}
	if u.Status != domain.UserStatusEnabled {
		t.Errorf("Status = %q, want %q", u.Status, domain.UserStatusEnabled)
	}
}

func TestGetUserByID(t *testing.T) {
	d, ctx := setupTestDAO(t)

	created, _ := d.CreateUser(ctx, "john", "John Doe", "john@example.com", "hashedpw", "")
	got, err := d.GetUserByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Username != "john" {
		t.Errorf("Username = %q, want %q", got.Username, "john")
	}
}

func TestGetUserByUsername(t *testing.T) {
	d, ctx := setupTestDAO(t)

	d.CreateUser(ctx, "jane", "Jane Doe", "jane@example.com", "hashedpw", "")
	got, err := d.GetUserByUsername(ctx, "jane")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.Email != "jane@example.com" {
		t.Errorf("Email = %q, want %q", got.Email, "jane@example.com")
	}
}

func TestListUsers(t *testing.T) {
	d, ctx := setupTestDAO(t)

	for i := 0; i < 5; i++ {
		name := "user" + string(rune('A'+i))
		d.CreateUser(ctx, name, "User "+name, name+"@example.com", "hashedpw", "")
	}

	result, err := d.ListUsers(ctx, 1, 3, "")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if result.Total != 5 {
		t.Errorf("Total = %d, want 5", result.Total)
	}
	if len(result.Items) != 3 {
		t.Errorf("Items count = %d, want 3", len(result.Items))
	}
}

func TestListUsersWithSearch(t *testing.T) {
	d, ctx := setupTestDAO(t)

	d.CreateUser(ctx, "alice", "Alice Smith", "alice@example.com", "hashedpw", "")
	d.CreateUser(ctx, "bob", "Bob Jones", "bob@example.com", "hashedpw", "")

	result, err := d.ListUsers(ctx, 1, 10, "alice")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("Total = %d, want 1", result.Total)
	}
}

func TestUpdateUser(t *testing.T) {
	d, ctx := setupTestDAO(t)

	created, _ := d.CreateUser(ctx, "john", "John Doe", "john@example.com", "hashedpw", "")
	newName := "John Smith"
	updated, err := d.UpdateUser(ctx, created.ID, domain.UpdateUserInput{DisplayName: &newName})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.DisplayName != "John Smith" {
		t.Errorf("DisplayName = %q, want %q", updated.DisplayName, "John Smith")
	}
}

func TestDeleteUser(t *testing.T) {
	d, ctx := setupTestDAO(t)

	created, _ := d.CreateUser(ctx, "john", "John Doe", "john@example.com", "hashedpw", "")
	if err := d.DeleteUser(ctx, created.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	_, err := d.GetUserByID(ctx, created.ID)
	if err == nil {
		t.Error("expected error after deleting user, got nil")
	}
}

func TestUpdateUserStatus(t *testing.T) {
	d, ctx := setupTestDAO(t)

	created, _ := d.CreateUser(ctx, "john", "John Doe", "john@example.com", "hashedpw", "")
	if err := d.UpdateUserStatus(ctx, created.ID, "disabled"); err != nil {
		t.Fatalf("UpdateUserStatus: %v", err)
	}
	got, _ := d.GetUserByID(ctx, created.ID)
	if got.Status != domain.UserStatusDisabled {
		t.Errorf("Status = %q, want %q", got.Status, domain.UserStatusDisabled)
	}
}
