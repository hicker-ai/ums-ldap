package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/qinzj/ums-ldap/internal/dao"
	"github.com/qinzj/ums-ldap/internal/domain"
)

// GroupService handles group business logic.
type GroupService struct {
	dao *dao.DAO
}

// NewGroupService creates a new GroupService.
func NewGroupService(d *dao.DAO) *GroupService {
	return &GroupService{dao: d}
}

// CreateGroup creates a new group, validating parent exists if specified.
func (s *GroupService) CreateGroup(ctx context.Context, input domain.CreateGroupInput) (*domain.Group, error) {
	if input.ParentID != nil {
		if _, err := s.dao.GetGroupByID(ctx, *input.ParentID); err != nil {
			return nil, fmt.Errorf("parent group not found: %w", err)
		}
	}
	return s.dao.CreateGroup(ctx, input.Name, input.Description, input.ParentID)
}

// GetGroup retrieves a group by ID with users and children.
func (s *GroupService) GetGroup(ctx context.Context, id uuid.UUID) (*domain.Group, error) {
	return s.dao.GetGroupByID(ctx, id)
}

// ListGroups returns all groups as a flat list (frontend builds tree).
func (s *GroupService) ListGroups(ctx context.Context) ([]*domain.Group, error) {
	return s.dao.ListGroups(ctx)
}

// UpdateGroup updates group fields.
func (s *GroupService) UpdateGroup(ctx context.Context, id uuid.UUID, input domain.UpdateGroupInput) (*domain.Group, error) {
	if input.ParentID != nil && *input.ParentID == id {
		return nil, fmt.Errorf("group cannot be its own parent")
	}
	return s.dao.UpdateGroup(ctx, id, input)
}

// DeleteGroup deletes a group.
func (s *GroupService) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	return s.dao.DeleteGroup(ctx, id)
}

// AddMembers adds users to a group.
func (s *GroupService) AddMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	return s.dao.AddMembers(ctx, groupID, userIDs)
}

// RemoveMember removes a user from a group.
func (s *GroupService) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return s.dao.RemoveMember(ctx, groupID, userID)
}

// GetGroupMembers returns all users in a group.
func (s *GroupService) GetGroupMembers(ctx context.Context, groupID uuid.UUID) ([]*domain.User, error) {
	return s.dao.GetGroupMembers(ctx, groupID)
}

// GetUserGroups returns all groups a user belongs to.
func (s *GroupService) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*domain.Group, error) {
	return s.dao.GetUserGroups(ctx, userID)
}

// AllGroups returns all groups with users (for LDAP search).
func (s *GroupService) AllGroups(ctx context.Context) ([]*domain.Group, error) {
	return s.dao.AllGroups(ctx)
}
