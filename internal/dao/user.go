package dao

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/ent"
	"github.com/qinzj/ums-ldap/internal/ent/user"
)

// CreateUser creates a new user in the database.
func (d *DAO) CreateUser(ctx context.Context, username, displayName, email, passwordHash, phone string) (*domain.User, error) {
	u, err := d.client.User.Create().
		SetUsername(username).
		SetDisplayName(displayName).
		SetEmail(email).
		SetPasswordHash(passwordHash).
		SetPhone(phone).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return entUserToDomain(u), nil
}

// GetUserByID retrieves a user by ID with groups eagerly loaded.
func (d *DAO) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, err := d.client.User.Query().
		Where(user.ID(id)).
		WithGroups().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying user by id: %w", err)
	}
	return entUserToDomainWithGroups(u), nil
}

// GetUserByUsername retrieves a user by username.
func (d *DAO) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	u, err := d.client.User.Query().
		Where(user.UsernameEQ(username)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying user by username: %w", err)
	}
	return entUserToDomain(u), nil
}

// ListUsers returns a paginated list of users, optionally filtered by search.
func (d *DAO) ListUsers(ctx context.Context, page, pageSize int, search string) (*domain.ListResult[domain.User], error) {
	query := d.client.User.Query()

	if search != "" {
		query = query.Where(
			user.Or(
				user.UsernameContains(search),
				user.DisplayNameContains(search),
				user.EmailContains(search),
			),
		)
	}

	total, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}

	offset := (page - 1) * pageSize
	users, err := query.
		Offset(offset).
		Limit(pageSize).
		Order(ent.Asc(user.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}

	items := make([]*domain.User, len(users))
	for i, u := range users {
		items[i] = entUserToDomain(u)
	}

	return &domain.ListResult[domain.User]{
		Items:    items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// UpdateUser updates user fields.
func (d *DAO) UpdateUser(ctx context.Context, id uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
	update := d.client.User.UpdateOneID(id)
	if input.DisplayName != nil {
		update = update.SetDisplayName(*input.DisplayName)
	}
	if input.Email != nil {
		update = update.SetEmail(*input.Email)
	}
	if input.Phone != nil {
		update = update.SetPhone(*input.Phone)
	}

	u, err := update.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}
	return entUserToDomain(u), nil
}

// UpdateUserPassword updates a user's password hash.
func (d *DAO) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := d.client.User.UpdateOneID(id).
		SetPasswordHash(passwordHash).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("updating user password: %w", err)
	}
	return nil
}

// UpdateUserStatus updates a user's status.
func (d *DAO) UpdateUserStatus(ctx context.Context, id uuid.UUID, status user.Status) error {
	_, err := d.client.User.UpdateOneID(id).
		SetStatus(status).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("updating user status: %w", err)
	}
	return nil
}

// DeleteUser deletes a user by ID.
func (d *DAO) DeleteUser(ctx context.Context, id uuid.UUID) error {
	if err := d.client.User.DeleteOneID(id).Exec(ctx); err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	return nil
}

// GetUserGroups returns all groups a user belongs to.
func (d *DAO) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*domain.Group, error) {
	u, err := d.client.User.Query().
		Where(user.ID(userID)).
		WithGroups().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying user groups: %w", err)
	}

	groups := make([]*domain.Group, len(u.Edges.Groups))
	for i, g := range u.Edges.Groups {
		groups[i] = entGroupToDomain(g)
	}
	return groups, nil
}

// AllUsers returns all users (for LDAP search).
func (d *DAO) AllUsers(ctx context.Context) ([]*domain.User, error) {
	users, err := d.client.User.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying all users: %w", err)
	}
	items := make([]*domain.User, len(users))
	for i, u := range users {
		items[i] = entUserToDomain(u)
	}
	return items, nil
}

func entUserToDomain(u *ent.User) *domain.User {
	return &domain.User{
		ID:           u.ID,
		Username:     u.Username,
		DisplayName:  u.DisplayName,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		Phone:        u.Phone,
		Status:       domain.UserStatus(u.Status),
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}

func entUserToDomainWithGroups(u *ent.User) *domain.User {
	du := entUserToDomain(u)
	if u.Edges.Groups != nil {
		du.Groups = make([]*domain.Group, len(u.Edges.Groups))
		for i, g := range u.Edges.Groups {
			du.Groups[i] = entGroupToDomain(g)
		}
	}
	return du
}
