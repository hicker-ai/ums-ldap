package http

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qinzj/ums-ldap/internal/service"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	authService *service.AuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authSvc *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authSvc}
}

// LoginReq is the login request DTO.
type LoginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login godoc
// @Summary      User login
// @Description  Authenticate with username and password, returns JWT token
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request  body      LoginReq  true  "Login credentials"
// @Success      200      {object}  Response{data=object{token=string,user=object{id=string,username=string,display_name=string}}}
// @Failure      400      {object}  Response
// @Failure      401      {object}  Response
// @Router       /api/v1/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	token, u, err := h.authService.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		Error(c, http.StatusUnauthorized, "authentication failed")
		return
	}

	OK(c, gin.H{
		"token": token,
		"user": gin.H{
			"id":           u.ID,
			"username":     u.Username,
			"display_name": u.DisplayName,
		},
	})
}

// Logout godoc
// @Summary      User logout
// @Description  Stateless logout (JWT is not invalidated server-side)
// @Tags         Auth
// @Produce      json
// @Success      200  {object}  Response
// @Router       /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	OK(c, nil)
}
