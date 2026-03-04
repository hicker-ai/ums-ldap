package http

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/service"
)

// UserHandler handles user CRUD endpoints.
type UserHandler struct {
	userService  *service.UserService
	groupService *service.GroupService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(userSvc *service.UserService, groupSvc *service.GroupService) *UserHandler {
	return &UserHandler{userService: userSvc, groupService: groupSvc}
}

// CreateUserReq is the request DTO for creating a user.
type CreateUserReq struct {
	Username    string `json:"username" binding:"required,max=64"`
	DisplayName string `json:"display_name" binding:"required,max=128"`
	Email       string `json:"email" binding:"required,email,max=255"`
	Password    string `json:"password" binding:"required,min=8"`
	Phone       string `json:"phone,omitempty" binding:"omitempty,max=32"`
}

// UpdateUserReq is the request DTO for updating a user.
type UpdateUserReq struct {
	DisplayName *string `json:"display_name,omitempty" binding:"omitempty,max=128"`
	Email       *string `json:"email,omitempty" binding:"omitempty,email,max=255"`
	Phone       *string `json:"phone,omitempty" binding:"omitempty,max=32"`
}

// ChangePasswordReq is the request DTO for changing password.
type ChangePasswordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// SetStatusReq is the request DTO for setting user status.
type SetStatusReq struct {
	Status string `json:"status" binding:"required,oneof=enabled disabled"`
}

// Create godoc
// @Summary      Create user
// @Description  Create a new user (no authentication required)
// @Tags         User
// @Accept       json
// @Produce      json
// @Param        request  body      CreateUserReq  true  "User info"
// @Success      200      {object}  Response{data=domain.User}
// @Failure      400      {object}  Response
// @Failure      500      {object}  Response
// @Router       /api/v1/users [post]
func (h *UserHandler) Create(c *gin.Context) {
	var req CreateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	u, err := h.userService.CreateUser(c.Request.Context(), domain.CreateUserInput{
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Password:    req.Password,
		Phone:       req.Phone,
	})
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to create user: "+err.Error())
		return
	}
	OK(c, u)
}

// Get godoc
// @Summary      Get user
// @Description  Retrieve a user by ID
// @Tags         User
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Param        id             path      string  true  "User ID (UUID)"
// @Success      200            {object}  Response{data=domain.User}
// @Failure      400            {object}  Response
// @Failure      404            {object}  Response
// @Router       /api/v1/users/{id} [get]
func (h *UserHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	u, err := h.userService.GetUser(c.Request.Context(), id)
	if err != nil {
		Error(c, http.StatusNotFound, "user not found")
		return
	}
	OK(c, u)
}

// List godoc
// @Summary      List users
// @Description  List users with pagination and optional search
// @Tags         User
// @Produce      json
// @Param        Authorization  header    string  true   "Bearer token"
// @Param        page           query     int     false  "Page number (default 1)"
// @Param        page_size      query     int     false  "Page size (default 20, max 100)"
// @Param        search         query     string  false  "Search by username, display_name, or email"
// @Success      200            {object}  Response{data=domain.ListResult[domain.User]}
// @Failure      500            {object}  Response
// @Router       /api/v1/users [get]
func (h *UserHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")

	result, err := h.userService.ListUsers(c.Request.Context(), domain.ListUsersInput{
		Page:     page,
		PageSize: pageSize,
		Search:   search,
	})
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to list users")
		return
	}
	OK(c, result)
}

// Update godoc
// @Summary      Update user
// @Description  Update user fields (display_name, email, phone)
// @Tags         User
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string         true  "Bearer token"
// @Param        id             path      string         true  "User ID (UUID)"
// @Param        request        body      UpdateUserReq  true  "Fields to update"
// @Success      200            {object}  Response{data=domain.User}
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/users/{id} [put]
func (h *UserHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	var req UpdateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	u, err := h.userService.UpdateUser(c.Request.Context(), id, domain.UpdateUserInput{
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Phone:       req.Phone,
	})
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to update user")
		return
	}
	OK(c, u)
}

// Delete godoc
// @Summary      Delete user
// @Description  Delete a user by ID
// @Tags         User
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Param        id             path      string  true  "User ID (UUID)"
// @Success      200            {object}  Response
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/users/{id} [delete]
func (h *UserHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := h.userService.DeleteUser(c.Request.Context(), id); err != nil {
		Error(c, http.StatusInternalServerError, "failed to delete user")
		return
	}
	OK(c, nil)
}

// ChangePassword godoc
// @Summary      Change password
// @Description  Change a user's password (requires old password verification)
// @Tags         User
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string             true  "Bearer token"
// @Param        id             path      string             true  "User ID (UUID)"
// @Param        request        body      ChangePasswordReq  true  "Old and new password"
// @Success      200            {object}  Response
// @Failure      400            {object}  Response
// @Router       /api/v1/users/{id}/password [put]
func (h *UserHandler) ChangePassword(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	var req ChangePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if err := h.userService.ChangePassword(c.Request.Context(), id, req.OldPassword, req.NewPassword); err != nil {
		Error(c, http.StatusBadRequest, "failed to change password: "+err.Error())
		return
	}
	OK(c, nil)
}

// SetStatus godoc
// @Summary      Set user status
// @Description  Enable or disable a user account
// @Tags         User
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string        true  "Bearer token"
// @Param        id             path      string        true  "User ID (UUID)"
// @Param        request        body      SetStatusReq  true  "Status: enabled | disabled"
// @Success      200            {object}  Response
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/users/{id}/status [put]
func (h *UserHandler) SetStatus(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	var req SetStatusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if err := h.userService.SetUserStatus(c.Request.Context(), id, domain.UserStatus(req.Status)); err != nil {
		Error(c, http.StatusInternalServerError, "failed to set status")
		return
	}
	OK(c, nil)
}

// GetGroups godoc
// @Summary      Get user groups
// @Description  Return all groups a user belongs to
// @Tags         User
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Param        id             path      string  true  "User ID (UUID)"
// @Success      200            {object}  Response{data=[]domain.Group}
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/users/{id}/groups [get]
func (h *UserHandler) GetGroups(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	groups, err := h.groupService.GetUserGroups(c.Request.Context(), id)
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to get user groups")
		return
	}
	OK(c, groups)
}
