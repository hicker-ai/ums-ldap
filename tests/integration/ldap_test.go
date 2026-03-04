package integration

import (
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/qinzj/ums-ldap/internal/domain"
)

func ensureUser(t *testing.T, input domain.CreateUserInput) *domain.User {
	t.Helper()
	ctx := t.Context()
	if u, err := userSvc.GetUserByUsername(ctx, input.Username); err == nil {
		return u
	}
	u, err := userSvc.CreateUser(ctx, input)
	if err != nil {
		t.Fatalf("create user %s: %v", input.Username, err)
	}
	return u
}

func ensureGroup(t *testing.T, name, desc string, memberIDs []uuid.UUID) *domain.Group {
	t.Helper()
	ctx := t.Context()
	g, err := groupSvc.CreateGroup(ctx, domain.CreateGroupInput{
		Name:        name,
		Description: desc,
	})
	if err != nil {
		// Group may already exist; try to find by listing
		return nil
	}
	if len(memberIDs) > 0 {
		_ = groupSvc.AddMembers(ctx, g.ID, memberIDs)
	}
	return g
}

func ldapDial(t *testing.T) *goldap.Conn {
	t.Helper()
	conn, err := goldap.Dial("tcp", ldapAddr)
	if err != nil {
		t.Fatalf("LDAP dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestLDAPBind(t *testing.T) {
	ensureUser(t, domain.CreateUserInput{
		Username:    "binduser",
		DisplayName: "Bind User",
		Email:       "bind@test.com",
		Password:    "bindpass123",
	})

	t.Run("successful bind", func(t *testing.T) {
		conn := ldapDial(t)
		err := conn.Bind("uid=binduser,ou=users,"+testBaseDN, "bindpass123")
		if err != nil {
			t.Errorf("bind should succeed: %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		conn := ldapDial(t)
		err := conn.Bind("uid=binduser,ou=users,"+testBaseDN, "wrongpassword")
		if err == nil {
			t.Error("bind with wrong password should fail")
		}
	})

	t.Run("disabled user bind", func(t *testing.T) {
		u := ensureUser(t, domain.CreateUserInput{
			Username:    "disabledldap",
			DisplayName: "Disabled LDAP",
			Email:       "disabled@test.com",
			Password:    "password123",
		})
		_ = userSvc.SetUserStatus(t.Context(), u.ID, domain.UserStatusDisabled)

		conn := ldapDial(t)
		err := conn.Bind("uid=disabledldap,ou=users,"+testBaseDN, "password123")
		if err == nil {
			t.Error("bind for disabled user should fail")
		}
	})
}

func TestLDAPSearchFilters(t *testing.T) {
	// Create test users
	u1 := ensureUser(t, domain.CreateUserInput{
		Username: "suser1", DisplayName: "Search Alpha", Email: "salpha@test.com", Password: "password123",
	})
	u2 := ensureUser(t, domain.CreateUserInput{
		Username: "suser2", DisplayName: "Search Beta", Email: "sbeta@test.com", Password: "password123",
	})
	ensureUser(t, domain.CreateUserInput{
		Username: "suser3", DisplayName: "Search Gamma", Email: "sgamma@example.org", Password: "password123",
	})

	// Create group with members
	ensureGroup(t, "search-admins", "Search Admin Group", []uuid.UUID{u1.ID, u2.ID})

	t.Run("search all users by objectClass", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(objectClass=inetOrgPerson)",
			Attributes: []string{"uid", "cn", "mail"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) < 3 {
			t.Errorf("expected >= 3 user entries, got %d", len(result.Entries))
		}
	})

	t.Run("search specific user by uid", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(uid=suser1)",
			Attributes: []string{"uid", "cn"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) != 1 {
			t.Errorf("expected 1 entry, got %d", len(result.Entries))
		}
	})

	t.Run("AND filter with objectClass and substring", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN: testBaseDN,
			Scope:  goldap.ScopeWholeSubtree,
			Filter: "(&(objectClass=inetOrgPerson)(mail=*@test.com))",
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		// Should find users with @test.com emails, not @example.org
		for _, entry := range result.Entries {
			mail := entry.GetAttributeValue("mail")
			if mail != "" && len(mail) >= 9 && mail[len(mail)-9:] != "@test.com" {
				t.Errorf("unexpected mail %q in results", mail)
			}
		}
	})

	t.Run("OR filter", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(|(uid=suser1)(uid=suser2))",
			Attributes: []string{"uid"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) != 2 {
			t.Errorf("expected 2 entries for OR, got %d", len(result.Entries))
		}
	})

	t.Run("NOT filter", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(&(objectClass=inetOrgPerson)(!(uid=suser1)))",
			Attributes: []string{"uid"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		for _, entry := range result.Entries {
			if entry.GetAttributeValue("uid") == "suser1" {
				t.Error("suser1 should be excluded by NOT filter")
			}
		}
	})

	t.Run("substring prefix", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(cn=Search*)",
			Attributes: []string{"cn"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) < 3 {
			t.Errorf("expected >= 3 entries with cn=Search*, got %d", len(result.Entries))
		}
	})

	t.Run("substring final", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(cn=*Alpha)",
			Attributes: []string{"cn"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) != 1 {
			t.Errorf("expected 1 entry with cn=*Alpha, got %d", len(result.Entries))
		}
	})

	t.Run("group search with objectClass", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(objectClass=groupOfNames)",
			Attributes: []string{"cn", "member"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) < 1 {
			t.Errorf("expected >= 1 group entry, got %d", len(result.Entries))
		}
	})

	t.Run("group search with substring", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN: testBaseDN,
			Scope:  goldap.ScopeWholeSubtree,
			Filter: "(&(objectClass=groupOfNames)(cn=search*))",
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) < 1 {
			t.Errorf("expected >= 1 group with cn=search*, got %d", len(result.Entries))
		}
	})

	t.Run("nested complex filter", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(&(|(cn=Search Alpha)(cn=Search Beta))(objectClass=inetOrgPerson))",
			Attributes: []string{"uid"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) != 2 {
			t.Errorf("expected 2 entries for nested filter, got %d", len(result.Entries))
		}
	})

	t.Run("GTE filter", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN: testBaseDN,
			Scope:  goldap.ScopeWholeSubtree,
			Filter: "(&(objectClass=inetOrgPerson)(uid>=suser2))",
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) < 2 {
			t.Errorf("expected >= 2 entries for GTE, got %d", len(result.Entries))
		}
	})

	t.Run("LTE filter", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN: testBaseDN,
			Scope:  goldap.ScopeWholeSubtree,
			Filter: "(&(objectClass=inetOrgPerson)(uid<=suser1))",
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		found := false
		for _, e := range result.Entries {
			if e.GetAttributeValue("uid") == "suser1" {
				found = true
			}
		}
		if !found {
			t.Error("suser1 should be in LTE results")
		}
	})

	t.Run("present filter objectClass=*", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN: testBaseDN,
			Scope:  goldap.ScopeWholeSubtree,
			Filter: "(objectClass=*)",
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) < 4 {
			t.Errorf("expected >= 4 entries for present filter, got %d", len(result.Entries))
		}
	})

	t.Run("size limit", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:    testBaseDN,
			Scope:     goldap.ScopeWholeSubtree,
			Filter:    "(objectClass=*)",
			SizeLimit: 2,
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) > 2 {
			t.Errorf("expected <= 2 entries with size limit, got %d", len(result.Entries))
		}
	})
}

func TestLDAPGroupMembers(t *testing.T) {
	u1 := ensureUser(t, domain.CreateUserInput{
		Username:    "gmember1",
		DisplayName: "Group Member One",
		Email:       "gm1@test.com",
		Password:    "password123",
	})
	u2 := ensureUser(t, domain.CreateUserInput{
		Username:    "gmember2",
		DisplayName: "Group Member Two",
		Email:       "gm2@test.com",
		Password:    "password123",
	})

	ensureGroup(t, "member-test-group", "Test group for member DN", []uuid.UUID{u1.ID, u2.ID})

	t.Run("group has member DNs", func(t *testing.T) {
		conn := ldapDial(t)
		result, err := conn.Search(&goldap.SearchRequest{
			BaseDN:     testBaseDN,
			Scope:      goldap.ScopeWholeSubtree,
			Filter:     "(cn=member-test-group)",
			Attributes: []string{"cn", "member"},
		})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(result.Entries) != 1 {
			t.Fatalf("expected 1 group entry, got %d", len(result.Entries))
		}
		members := result.Entries[0].GetAttributeValues("member")
		if len(members) < 2 {
			t.Errorf("expected >= 2 member DNs, got %d", len(members))
		}
	})
}
