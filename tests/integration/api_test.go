package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/qinzj/ums-ldap/internal/domain"
)

func TestAuthFlow(t *testing.T) {
	// Create an admin user via service (bootstrap)
	ctx := t
	_ = ctx
	adminUser, err := userSvc.CreateUser(t.Context(), domain.CreateUserInput{
		Username:    "authadmin",
		DisplayName: "Auth Admin",
		Email:       "authadmin@test.com",
		Password:    "password123",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	_ = adminUser

	t.Run("login success", func(t *testing.T) {
		resp := doAPI(t, "POST", "/api/v1/auth/login", map[string]string{
			"username": "authadmin",
			"password": "password123",
		}, "")
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("expected success, got: %s", r.Message)
		}
		var data struct {
			Token string `json:"token"`
		}
		json.Unmarshal(r.Data, &data)
		if data.Token == "" {
			t.Error("expected non-empty token")
		}
	})

	t.Run("login wrong password", func(t *testing.T) {
		resp := doAPI(t, "POST", "/api/v1/auth/login", map[string]string{
			"username": "authadmin",
			"password": "wrongpassword",
		}, "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	t.Run("access without token", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/users", nil, "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	t.Run("access with invalid token", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/users", nil, "invalid-token-here")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})
}

func TestUserLifecycle(t *testing.T) {
	// Bootstrap admin
	userSvc.CreateUser(t.Context(), domain.CreateUserInput{
		Username:    "lifecycleadmin",
		DisplayName: "Lifecycle Admin",
		Email:       "lcadmin@test.com",
		Password:    "password123",
	})
	token := loginAndGetToken(t, "lifecycleadmin", "password123")

	// Create user
	var userID string
	t.Run("create user", func(t *testing.T) {
		userID = createUserViaAPI(t, token, map[string]string{
			"username":     "testuser1",
			"display_name": "Test User 1",
			"email":        "testuser1@test.com",
			"password":     "password123",
			"phone":        "1234567890",
		})
		if userID == "" {
			t.Fatal("expected non-empty user ID")
		}
	})

	// Get user
	t.Run("get user", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/users/"+userID, nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("get user failed: %s", r.Message)
		}
		var data struct {
			Username string `json:"username"`
		}
		json.Unmarshal(r.Data, &data)
		if data.Username != "testuser1" {
			t.Errorf("username = %q, want testuser1", data.Username)
		}
	})

	// List users with search
	t.Run("list users with search", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/users?search=testuser1", nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("list users failed: %s", r.Message)
		}
		var data struct {
			Total int `json:"total"`
		}
		json.Unmarshal(r.Data, &data)
		if data.Total < 1 {
			t.Errorf("expected at least 1 result, got %d", data.Total)
		}
	})

	// List users with pagination
	t.Run("list users with pagination", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/users?page=1&page_size=1", nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("list users failed: %s", r.Message)
		}
		var data struct {
			Items []json.RawMessage `json:"items"`
			Total int               `json:"total"`
		}
		json.Unmarshal(r.Data, &data)
		if len(data.Items) != 1 {
			t.Errorf("expected 1 item per page, got %d", len(data.Items))
		}
	})

	// Update user
	t.Run("update user", func(t *testing.T) {
		newName := "Updated User 1"
		resp := doAPI(t, "PUT", "/api/v1/users/"+userID, map[string]interface{}{
			"display_name": newName,
		}, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("update user failed: %s", r.Message)
		}
		var data struct {
			DisplayName string `json:"display_name"`
		}
		json.Unmarshal(r.Data, &data)
		if data.DisplayName != newName {
			t.Errorf("DisplayName = %q, want %q", data.DisplayName, newName)
		}
	})

	// Change password
	t.Run("change password", func(t *testing.T) {
		resp := doAPI(t, "PUT", "/api/v1/users/"+userID+"/password", map[string]string{
			"old_password": "password123",
			"new_password": "newpass12345",
		}, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("change password failed: %s", r.Message)
		}
	})

	// Set status (disable)
	t.Run("disable user", func(t *testing.T) {
		resp := doAPI(t, "PUT", "/api/v1/users/"+userID+"/status", map[string]string{
			"status": "disabled",
		}, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("set status failed: %s", r.Message)
		}
	})

	// Delete user
	t.Run("delete user", func(t *testing.T) {
		resp := doAPI(t, "DELETE", "/api/v1/users/"+userID, nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("delete user failed: %s", r.Message)
		}

		// Verify deleted
		resp2 := doAPI(t, "GET", "/api/v1/users/"+userID, nil, token)
		if resp2.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 after delete, got %d", resp2.StatusCode)
		}
		resp2.Body.Close()
	})
}

func TestGroupLifecycle(t *testing.T) {
	// Bootstrap admin
	userSvc.CreateUser(t.Context(), domain.CreateUserInput{
		Username:    "groupadmin",
		DisplayName: "Group Admin",
		Email:       "gadmin@test.com",
		Password:    "password123",
	})
	token := loginAndGetToken(t, "groupadmin", "password123")

	// Create member user
	memberID := createUserViaAPI(t, token, map[string]string{
		"username":     "groupmember",
		"display_name": "Group Member",
		"email":        "member@test.com",
		"password":     "password123",
	})

	// Create parent group
	var parentID string
	t.Run("create parent group", func(t *testing.T) {
		parentID = createGroupViaAPI(t, token, map[string]interface{}{
			"name":        "parent-group",
			"description": "Parent Group",
		})
		if parentID == "" {
			t.Fatal("expected non-empty group ID")
		}
	})

	// Create child group
	var childID string
	t.Run("create child group", func(t *testing.T) {
		childID = createGroupViaAPI(t, token, map[string]interface{}{
			"name":        "child-group",
			"description": "Child Group",
			"parent_id":   parentID,
		})
		if childID == "" {
			t.Fatal("expected non-empty child group ID")
		}
	})

	// Get group (with hierarchy)
	t.Run("get parent group", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/groups/"+parentID, nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("get group failed: %s", r.Message)
		}
	})

	// List groups
	t.Run("list groups", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/groups", nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("list groups failed: %s", r.Message)
		}
	})

	// Add members
	t.Run("add member to group", func(t *testing.T) {
		resp := doAPI(t, "POST", "/api/v1/groups/"+parentID+"/members", map[string]interface{}{
			"user_ids": []string{memberID},
		}, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("add member failed: %s", r.Message)
		}
	})

	// Get members
	t.Run("get members", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/groups/"+parentID+"/members", nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("get members failed: %s", r.Message)
		}
	})

	// Get user groups
	t.Run("get user groups", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/users/"+memberID+"/groups", nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("get user groups failed: %s", r.Message)
		}
	})

	// Remove member
	t.Run("remove member", func(t *testing.T) {
		resp := doAPI(t, "DELETE", "/api/v1/groups/"+parentID+"/members/"+memberID, nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("remove member failed: %s", r.Message)
		}
	})

	// Delete child first, then parent
	t.Run("delete child group", func(t *testing.T) {
		resp := doAPI(t, "DELETE", "/api/v1/groups/"+childID, nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("delete child group failed: %s", r.Message)
		}
	})

	t.Run("delete parent group", func(t *testing.T) {
		resp := doAPI(t, "DELETE", "/api/v1/groups/"+parentID, nil, token)
		r := parseResponse(t, resp)
		if r.Code != 0 {
			t.Fatalf("delete parent group failed: %s", r.Message)
		}
	})
}

func TestValidationErrors(t *testing.T) {
	userSvc.CreateUser(t.Context(), domain.CreateUserInput{
		Username:    "valadmin",
		DisplayName: "Val Admin",
		Email:       "valadmin@test.com",
		Password:    "password123",
	})
	token := loginAndGetToken(t, "valadmin", "password123")

	t.Run("create user missing required fields", func(t *testing.T) {
		resp := doAPI(t, "POST", "/api/v1/users", map[string]string{
			"username": "incomplete",
		}, token)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	t.Run("get non-existent user", func(t *testing.T) {
		resp := doAPI(t, "GET", "/api/v1/users/00000000-0000-0000-0000-000000000000", nil, token)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	t.Run("create duplicate username", func(t *testing.T) {
		createUserViaAPI(t, token, map[string]string{
			"username":     "dupuser",
			"display_name": "Dup User",
			"email":        "dup1@test.com",
			"password":     "password123",
		})
		resp := doAPI(t, "POST", "/api/v1/users", map[string]string{
			"username":     "dupuser",
			"display_name": "Dup User 2",
			"email":        "dup2@test.com",
			"password":     "password123",
		}, token)
		if resp.StatusCode == http.StatusOK {
			r := parseResponse(t, resp)
			if r.Code == 0 {
				t.Error("expected error for duplicate username")
			}
		} else {
			resp.Body.Close()
		}
	})
}
