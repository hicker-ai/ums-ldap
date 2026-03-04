package dao

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/qinzj/ums-ldap/internal/ent/enttest"
)

func setupGroupTestDAO(t *testing.T) (*DAO, context.Context) {
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

func TestCreateGroup(t *testing.T) {
	d, ctx := setupGroupTestDAO(t)

	g, err := d.CreateGroup(ctx, "admins", "Admin group", nil)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if g.Name != "admins" {
		t.Errorf("Name = %q, want %q", g.Name, "admins")
	}
}

func TestCreateGroupWithParent(t *testing.T) {
	d, ctx := setupGroupTestDAO(t)

	parent, _ := d.CreateGroup(ctx, "engineering", "Engineering", nil)
	child, err := d.CreateGroup(ctx, "backend", "Backend team", &parent.ID)
	if err != nil {
		t.Fatalf("CreateGroup with parent: %v", err)
	}
	if child.ParentID == nil || *child.ParentID != parent.ID {
		t.Error("child.ParentID should match parent.ID")
	}
}

func TestGetGroupByID(t *testing.T) {
	d, ctx := setupGroupTestDAO(t)

	created, _ := d.CreateGroup(ctx, "admins", "Admin group", nil)
	got, err := d.GetGroupByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetGroupByID: %v", err)
	}
	if got.Name != "admins" {
		t.Errorf("Name = %q, want %q", got.Name, "admins")
	}
}

func TestListGroups(t *testing.T) {
	d, ctx := setupGroupTestDAO(t)

	d.CreateGroup(ctx, "admins", "Admins", nil)
	d.CreateGroup(ctx, "users", "Users", nil)

	groups, err := d.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("len(groups) = %d, want 2", len(groups))
	}
}

func TestDeleteGroup(t *testing.T) {
	d, ctx := setupGroupTestDAO(t)

	created, _ := d.CreateGroup(ctx, "admins", "Admin group", nil)
	if err := d.DeleteGroup(ctx, created.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	_, err := d.GetGroupByID(ctx, created.ID)
	if err == nil {
		t.Error("expected error after deleting group, got nil")
	}
}

func TestAddAndRemoveMembers(t *testing.T) {
	d, ctx := setupGroupTestDAO(t)

	g, _ := d.CreateGroup(ctx, "admins", "Admins", nil)
	u1, _ := d.CreateUser(ctx, "alice", "Alice", "alice@example.com", "hash", "")
	u2, _ := d.CreateUser(ctx, "bob", "Bob", "bob@example.com", "hash", "")

	if err := d.AddMembers(ctx, g.ID, []uuid.UUID{u1.ID, u2.ID}); err != nil {
		t.Fatalf("AddMembers: %v", err)
	}

	members, err := d.GetGroupMembers(ctx, g.ID)
	if err != nil {
		t.Fatalf("GetGroupMembers: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("len(members) = %d, want 2", len(members))
	}

	if err := d.RemoveMember(ctx, g.ID, u1.ID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	members, _ = d.GetGroupMembers(ctx, g.ID)
	if len(members) != 1 {
		t.Errorf("len(members) = %d, want 1", len(members))
	}
}

func TestGetUserGroups(t *testing.T) {
	d, ctx := setupGroupTestDAO(t)

	g1, _ := d.CreateGroup(ctx, "group1", "Group 1", nil)
	g2, _ := d.CreateGroup(ctx, "group2", "Group 2", nil)
	u, _ := d.CreateUser(ctx, "alice", "Alice", "alice@example.com", "hash", "")

	d.AddMembers(ctx, g1.ID, []uuid.UUID{u.ID})
	d.AddMembers(ctx, g2.ID, []uuid.UUID{u.ID})

	groups, err := d.GetUserGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("len(groups) = %d, want 2", len(groups))
	}
}
