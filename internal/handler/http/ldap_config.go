package http

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qinzj/ums-ldap/internal/config"
)

// LDAPConfigHandler handles LDAP configuration endpoints.
type LDAPConfigHandler struct {
	cfg *config.LDAPConfig
}

// NewLDAPConfigHandler creates a new LDAPConfigHandler.
func NewLDAPConfigHandler(cfg *config.LDAPConfig) *LDAPConfigHandler {
	return &LDAPConfigHandler{cfg: cfg}
}

// GetConfig godoc
// @Summary      Get LDAP config
// @Description  Return the current LDAP server configuration
// @Tags         LDAP
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Success      200            {object}  Response{data=object{base_dn=string,mode=string,port=int}}
// @Router       /api/v1/ldap/config [get]
func (h *LDAPConfigHandler) GetConfig(c *gin.Context) {
	OK(c, gin.H{
		"base_dn": h.cfg.BaseDN,
		"mode":    h.cfg.Mode,
		"port":    h.cfg.Port,
	})
}

// UpdateConfigReq is the request DTO for updating LDAP config.
type UpdateConfigReq struct {
	BaseDN string `json:"base_dn" binding:"required"`
	Mode   string `json:"mode" binding:"required,oneof=openldap activedirectory"`
	Port   int    `json:"port" binding:"required,min=1,max=65535"`
}

// UpdateConfig godoc
// @Summary      Update LDAP config
// @Description  Update the LDAP server configuration (base_dn, mode, port)
// @Tags         LDAP
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string           true  "Bearer token"
// @Param        request        body      UpdateConfigReq  true  "LDAP configuration"
// @Success      200            {object}  Response
// @Failure      400            {object}  Response
// @Router       /api/v1/ldap/config [put]
func (h *LDAPConfigHandler) UpdateConfig(c *gin.Context) {
	var req UpdateConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	h.cfg.BaseDN = req.BaseDN
	h.cfg.Mode = req.Mode
	h.cfg.Port = req.Port
	OK(c, nil)
}

// GetStatus godoc
// @Summary      Get LDAP status
// @Description  Return the LDAP server running status
// @Tags         LDAP
// @Produce      json
// @Param        Authorization  header    string  true  "Bearer token"
// @Success      200            {object}  Response{data=object{running=bool,port=int,mode=string}}
// @Router       /api/v1/ldap/status [get]
func (h *LDAPConfigHandler) GetStatus(c *gin.Context) {
	OK(c, gin.H{
		"running": true,
		"port":    h.cfg.Port,
		"mode":    h.cfg.Mode,
	})
}
