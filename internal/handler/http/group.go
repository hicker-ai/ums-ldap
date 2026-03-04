package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/service"
)

// GroupHandler handles group CRUD endpoints.
type GroupHandler struct {
	groupService *service.GroupService
}

// NewGroupHandler creates a new GroupHandler.
func NewGroupHandler(groupSvc *service.GroupService) *GroupHandler {
	return &GroupHandler{groupService: groupSvc}
}

// CreateGroupReq is the request DTO for creating a group.
type CreateGroupReq struct {
	Name        string  `json:"name" binding:"required,max=64"`
	Description string  `json:"description,omitempty" binding:"omitempty,max=255"`
	ParentID    *string `json:"parent_id,omitempty"`
}

// UpdateGroupReq is the request DTO for updating a group.
type UpdateGroupReq struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,max=64"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=255"`
	ParentID    *string `json:"parent_id,omitempty"`
}

// AddMembersReq is the request DTO for adding members to a group.
type AddMembersReq struct {
	UserIDs []string `json:"user_ids" binding:"required,min=1"`
}

// Create godoc
// @Summary      Create group
// @Description  Create a new user group, optionally with a parent group
// @Tags         Group
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string          true  "Bearer token"
// @Param        request        body      CreateGroupReq  true  "Group info"
// @Success      200            {object}  Response{data=domain.Group}
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/groups [post]
func (h *GroupHandler) Create(c *gin.Context) {
	var req CreateGroupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	input := domain.CreateGroupInput{
		Name:        req.Name,
		Description: req.Description,
	}
	if req.ParentID != nil {
		pid, err := uuid.Parse(*req.ParentID)
		if err != nil {
			Error(c, http.StatusBadRequest, "invalid parent_id")
			return
		}
		input.ParentID = &pid
	}

	g, err := h.groupService.CreateGroup(c.Request.Context(), input)
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to create group: "+err.Error())
		return
	}
	OK(c, g)
}

// Get godoc
// @Summary      Get group
// @Description  Retrieve a group by ID with children
// @Tags         Group
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Param        id             path      string  true  "Group ID (UUID)"
// @Success      200            {object}  Response{data=domain.Group}
// @Failure      400            {object}  Response
// @Failure      404            {object}  Response
// @Router       /api/v1/groups/{id} [get]
func (h *GroupHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid group id")
		return
	}

	g, err := h.groupService.GetGroup(c.Request.Context(), id)
	if err != nil {
		Error(c, http.StatusNotFound, "group not found")
		return
	}
	OK(c, g)
}

// List godoc
// @Summary      List groups
// @Description  List all groups
// @Tags         Group
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Success      200            {object}  Response{data=[]domain.Group}
// @Failure      500            {object}  Response
// @Router       /api/v1/groups [get]
func (h *GroupHandler) List(c *gin.Context) {
	groups, err := h.groupService.ListGroups(c.Request.Context())
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to list groups")
		return
	}
	OK(c, groups)
}

// Update godoc
// @Summary      Update group
// @Description  Update group fields (name, description, parent_id)
// @Tags         Group
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string          true  "Bearer token"
// @Param        id             path      string          true  "Group ID (UUID)"
// @Param        request        body      UpdateGroupReq  true  "Fields to update"
// @Success      200            {object}  Response{data=domain.Group}
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/groups/{id} [put]
func (h *GroupHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid group id")
		return
	}

	var req UpdateGroupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	input := domain.UpdateGroupInput{
		Name:        req.Name,
		Description: req.Description,
	}
	if req.ParentID != nil {
		pid, err := uuid.Parse(*req.ParentID)
		if err != nil {
			Error(c, http.StatusBadRequest, "invalid parent_id")
			return
		}
		input.ParentID = &pid
	}

	g, err := h.groupService.UpdateGroup(c.Request.Context(), id, input)
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to update group: "+err.Error())
		return
	}
	OK(c, g)
}

// Delete godoc
// @Summary      Delete group
// @Description  Delete a group by ID
// @Tags         Group
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Param        id             path      string  true  "Group ID (UUID)"
// @Success      200            {object}  Response
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/groups/{id} [delete]
func (h *GroupHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid group id")
		return
	}

	if err := h.groupService.DeleteGroup(c.Request.Context(), id); err != nil {
		Error(c, http.StatusInternalServerError, "failed to delete group")
		return
	}
	OK(c, nil)
}

// AddMembers godoc
// @Summary      Add members
// @Description  Add users to a group
// @Tags         Group
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string         true  "Bearer token"
// @Param        id             path      string         true  "Group ID (UUID)"
// @Param        request        body      AddMembersReq  true  "User IDs to add"
// @Success      200            {object}  Response
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/groups/{id}/members [post]
func (h *GroupHandler) AddMembers(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid group id")
		return
	}

	var req AddMembersReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	userIDs := make([]uuid.UUID, len(req.UserIDs))
	for i, idStr := range req.UserIDs {
		uid, err := uuid.Parse(idStr)
		if err != nil {
			Error(c, http.StatusBadRequest, "invalid user_id: "+idStr)
			return
		}
		userIDs[i] = uid
	}

	if err := h.groupService.AddMembers(c.Request.Context(), groupID, userIDs); err != nil {
		Error(c, http.StatusInternalServerError, "failed to add members")
		return
	}
	OK(c, nil)
}

// RemoveMember godoc
// @Summary      Remove member
// @Description  Remove a user from a group
// @Tags         Group
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Param        id             path      string  true  "Group ID (UUID)"
// @Param        uid            path      string  true  "User ID (UUID)"
// @Success      200            {object}  Response
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/groups/{id}/members/{uid} [delete]
func (h *GroupHandler) RemoveMember(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid group id")
		return
	}

	userID, err := uuid.Parse(c.Param("uid"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := h.groupService.RemoveMember(c.Request.Context(), groupID, userID); err != nil {
		Error(c, http.StatusInternalServerError, "failed to remove member")
		return
	}
	OK(c, nil)
}

// GetMembers godoc
// @Summary      Get group members
// @Description  Return all users in a group
// @Tags         Group
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Param        id             path      string  true  "Group ID (UUID)"
// @Success      200            {object}  Response{data=[]domain.User}
// @Failure      400            {object}  Response
// @Failure      500            {object}  Response
// @Router       /api/v1/groups/{id}/members [get]
func (h *GroupHandler) GetMembers(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		Error(c, http.StatusBadRequest, "invalid group id")
		return
	}

	users, err := h.groupService.GetGroupMembers(c.Request.Context(), id)
	if err != nil {
		Error(c, http.StatusInternalServerError, "failed to get group members")
		return
	}
	OK(c, users)
}
