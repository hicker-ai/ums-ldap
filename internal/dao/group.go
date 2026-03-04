package dao

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/ent"
	"github.com/qinzj/ums-ldap/internal/ent/group"
)

// CreateGroup creates a new group.
func (d *DAO) CreateGroup(ctx context.Context, name, description string, parentID *uuid.UUID) (*domain.Group, error) {
	create := d.client.Group.Create().
		SetName(name).
		SetDescription(description)
	if parentID != nil {
		create = create.SetParentID(*parentID)
	}

	g, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}
	return entGroupToDomain(g), nil
}

// GetGroupByID retrieves a group by ID with users and children eagerly loaded.
func (d *DAO) GetGroupByID(ctx context.Context, id uuid.UUID) (*domain.Group, error) {
	g, err := d.client.Group.Query().
		Where(group.ID(id)).
		WithUsers().
		WithChildren().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying group by id: %w", err)
	}
	return entGroupToDomainWithEdges(g), nil
}

// ListGroups returns all groups.
func (d *DAO) ListGroups(ctx context.Context) ([]*domain.Group, error) {
	groups, err := d.client.Group.Query().
		WithChildren().
		Order(ent.Asc(group.FieldName)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}

	items := make([]*domain.Group, len(groups))
	for i, g := range groups {
		items[i] = entGroupToDomainWithEdges(g)
	}
	return items, nil
}

// UpdateGroup updates group fields.
func (d *DAO) UpdateGroup(ctx context.Context, id uuid.UUID, input domain.UpdateGroupInput) (*domain.Group, error) {
	update := d.client.Group.UpdateOneID(id)
	if input.Name != nil {
		update = update.SetName(*input.Name)
	}
	if input.Description != nil {
		update = update.SetDescription(*input.Description)
	}
	if input.ParentID != nil {
		update = update.SetParentID(*input.ParentID)
	}

	g, err := update.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("updating group: %w", err)
	}
	return entGroupToDomain(g), nil
}

// DeleteGroup deletes a group by ID.
func (d *DAO) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	if err := d.client.Group.DeleteOneID(id).Exec(ctx); err != nil {
		return fmt.Errorf("deleting group: %w", err)
	}
	return nil
}

// AddMembers adds users to a group.
func (d *DAO) AddMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	_, err := d.client.Group.UpdateOneID(groupID).
		AddUserIDs(userIDs...).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("adding members to group: %w", err)
	}
	return nil
}

// RemoveMember removes a user from a group.
func (d *DAO) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	_, err := d.client.Group.UpdateOneID(groupID).
		RemoveUserIDs(userID).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("removing member from group: %w", err)
	}
	return nil
}

// GetGroupMembers returns all users in a group.
func (d *DAO) GetGroupMembers(ctx context.Context, groupID uuid.UUID) ([]*domain.User, error) {
	g, err := d.client.Group.Query().
		Where(group.ID(groupID)).
		WithUsers().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying group members: %w", err)
	}

	users := make([]*domain.User, len(g.Edges.Users))
	for i, u := range g.Edges.Users {
		users[i] = entUserToDomain(u)
	}
	return users, nil
}

// AllGroups returns all groups (for LDAP search).
func (d *DAO) AllGroups(ctx context.Context) ([]*domain.Group, error) {
	groups, err := d.client.Group.Query().
		WithUsers().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying all groups: %w", err)
	}
	items := make([]*domain.Group, len(groups))
	for i, g := range groups {
		items[i] = entGroupToDomainWithEdges(g)
	}
	return items, nil
}

func entGroupToDomain(g *ent.Group) *domain.Group {
	dg := &domain.Group{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		ParentID:    g.ParentID,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
	return dg
}

func entGroupToDomainWithEdges(g *ent.Group) *domain.Group {
	dg := entGroupToDomain(g)
	if g.Edges.Users != nil {
		dg.Users = make([]*domain.User, len(g.Edges.Users))
		for i, u := range g.Edges.Users {
			dg.Users[i] = entUserToDomain(u)
		}
	}
	if g.Edges.Children != nil {
		dg.Children = make([]*domain.Group, len(g.Edges.Children))
		for i, c := range g.Edges.Children {
			dg.Children[i] = entGroupToDomain(c)
		}
	}
	return dg
}
