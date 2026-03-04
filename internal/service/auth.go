package service

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qinzj/ums-ldap/internal/domain"
)

// AuthService handles authentication and JWT tokens.
type AuthService struct {
	userService *UserService
	jwtSecret   []byte
	expireHours int
}

// NewAuthService creates a new AuthService.
func NewAuthService(userSvc *UserService, jwtSecret string, expireHours int) *AuthService {
	return &AuthService{
		userService: userSvc,
		jwtSecret:   []byte(jwtSecret),
		expireHours: expireHours,
	}
}

// Claims represents JWT token claims.
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Login authenticates a user and returns a JWT token.
func (s *AuthService) Login(ctx context.Context, username, password string) (string, *domain.User, error) {
	u, err := s.userService.Authenticate(ctx, username, password)
	if err != nil {
		return "", nil, fmt.Errorf("authentication failed: %w", err)
	}

	claims := &Claims{
		UserID:   u.ID.String(),
		Username: u.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.expireHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", nil, fmt.Errorf("signing token: %w", err)
	}

	return tokenStr, u, nil
}

// ValidateToken validates a JWT token and returns the claims.
func (s *AuthService) ValidateToken(_ context.Context, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
