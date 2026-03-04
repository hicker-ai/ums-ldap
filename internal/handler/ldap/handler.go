package ldap

import (
	"context"

	"github.com/google/uuid"
	"github.com/jimlambrt/gldap"
	"go.uber.org/zap"

	"github.com/qinzj/ums-ldap/internal/config"
	"github.com/qinzj/ums-ldap/internal/domain"
	"github.com/qinzj/ums-ldap/internal/ldap/attrs"
	"github.com/qinzj/ums-ldap/internal/ldap/dn"
)

// UserService defines the user operations needed by LDAP handler.
type UserService interface {
	Authenticate(ctx context.Context, username, password string) (*domain.User, error)
	AllUsers(ctx context.Context) ([]*domain.User, error)
}

// GroupService defines the group operations needed by LDAP handler.
type GroupService interface {
	AllGroups(ctx context.Context) ([]*domain.Group, error)
}

// Handler handles LDAP protocol operations.
type Handler struct {
	userService  UserService
	groupService GroupService
	cfg          *config.LDAPConfig
	logger       *zap.Logger
}

// New creates a new LDAP Handler.
func New(userSvc UserService, groupSvc GroupService, cfg *config.LDAPConfig, logger *zap.Logger) *Handler {
	return &Handler{
		userService:  userSvc,
		groupService: groupSvc,
		cfg:          cfg,
		logger:       logger,
	}
}

// RegisterRoutes registers LDAP Bind and Search handlers on the mux.
func (h *Handler) RegisterRoutes(mux *gldap.Mux) {
	mux.Bind(h.handleBind)
	mux.Search(h.handleSearch)
}

func (h *Handler) buildUserDN(u *domain.User) string {
	return dn.BuildUserDN(u.Username, u.DisplayName, h.cfg.BaseDN, h.cfg.Mode)
}

func (h *Handler) buildGroupDN(g *domain.Group) string {
	return dn.BuildGroupDN(g.Name, h.cfg.BaseDN, h.cfg.Mode)
}

func (h *Handler) userToEntry(u *domain.User) *ldapEntry {
	userDN := h.buildUserDN(u)
	mapper := attrs.NewMapper(h.cfg.Mode)
	attrsMap := mapper.UserToLDAPAttrs(u.Username, u.DisplayName, u.Email, u.Phone, string(u.Status))

	// Add objectClass
	attrsMap["objectClass"] = mapper.UserObjectClasses()

	// Add dn as attribute
	attrsMap["dn"] = []string{userDN}

	return &ldapEntry{
		dn:    userDN,
		attrs: attrsMap,
	}
}

func (h *Handler) groupToEntry(g *domain.Group) *ldapEntry {
	groupDN := h.buildGroupDN(g)
	mapper := attrs.NewMapper(h.cfg.Mode)

	var memberDNs []string
	if g.Users != nil {
		for _, u := range g.Users {
			memberDNs = append(memberDNs, h.buildUserDN(u))
		}
	}

	attrsMap := mapper.GroupToLDAPAttrs(g.Name, g.Description, memberDNs)
	attrsMap["objectClass"] = mapper.GroupObjectClasses()
	attrsMap["dn"] = []string{groupDN}

	return &ldapEntry{
		dn:    groupDN,
		attrs: attrsMap,
	}
}

type ldapEntry struct {
	dn    string
	attrs map[string][]string
}

func (e *ldapEntry) matchesObjectClass(oc string) bool {
	for _, v := range e.attrs["objectClass"] {
		if equalFold(v, oc) {
			return true
		}
	}
	return false
}

func (e *ldapEntry) matchesAttr(attr, value string) bool {
	for _, v := range e.attrs[attr] {
		if v == value {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// allUserGroupIDs returns a map of user ID -> group IDs for LDAP memberOf support.
func buildUserGroupMap(groups []*domain.Group) map[uuid.UUID][]string {
	m := make(map[uuid.UUID][]string)
	for _, g := range groups {
		if g.Users != nil {
			for _, u := range g.Users {
				m[u.ID] = append(m[u.ID], g.Name)
			}
		}
	}
	return m
}
