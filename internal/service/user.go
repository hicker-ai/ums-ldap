package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/qinzj/ums-ldap/internal/dao"
	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/ent/user"
)

// UserService handles user business logic.
type UserService struct {
	dao *dao.DAO
}

// NewUserService creates a new UserService.
func NewUserService(d *dao.DAO) *UserService {
	return &UserService{dao: d}
}

// CreateUser creates a new user with bcrypt-hashed password.
func (s *UserService) CreateUser(ctx context.Context, input domain.CreateUserInput) (*domain.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	return s.dao.CreateUser(ctx, input.Username, input.DisplayName, input.Email, string(hash), input.Phone)
}

// GetUser retrieves a user by ID with groups.
func (s *UserService) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.dao.GetUserByID(ctx, id)
}

// GetUserByUsername retrieves a user by username.
func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	return s.dao.GetUserByUsername(ctx, username)
}

// ListUsers returns a paginated list of users.
func (s *UserService) ListUsers(ctx context.Context, input domain.ListUsersInput) (*domain.ListResult[domain.User], error) {
	if input.Page < 1 {
		input.Page = 1
	}
	if input.PageSize < 1 || input.PageSize > 100 {
		input.PageSize = 20
	}
	return s.dao.ListUsers(ctx, input.Page, input.PageSize, input.Search)
}

// UpdateUser partially updates a user.
func (s *UserService) UpdateUser(ctx context.Context, id uuid.UUID, input domain.UpdateUserInput) (*domain.User, error) {
	return s.dao.UpdateUser(ctx, id, input)
}

// DeleteUser deletes a user.
func (s *UserService) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return s.dao.DeleteUser(ctx, id)
}

// ChangePassword verifies the old password and sets the new one.
func (s *UserService) ChangePassword(ctx context.Context, id uuid.UUID, oldPassword, newPassword string) error {
	u, err := s.dao.GetUserByID(ctx, id)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("invalid old password: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}

	return s.dao.UpdateUserPassword(ctx, id, string(hash))
}

// SetUserStatus enables or disables a user.
func (s *UserService) SetUserStatus(ctx context.Context, id uuid.UUID, status domain.UserStatus) error {
	return s.dao.UpdateUserStatus(ctx, id, user.Status(status))
}

// Authenticate verifies a username/password combination. Used by both HTTP login and LDAP Bind.
func (s *UserService) Authenticate(ctx context.Context, username, password string) (*domain.User, error) {
	u, err := s.dao.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if u.Status != domain.UserStatusEnabled {
		return nil, fmt.Errorf("user %q is disabled", username)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	return u, nil
}

// AllUsers returns all users (for LDAP search).
func (s *UserService) AllUsers(ctx context.Context) ([]*domain.User, error) {
	return s.dao.AllUsers(ctx)
}
