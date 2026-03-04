package ldap

import (
	"context"

	"github.com/jimlambrt/gldap"
	"go.uber.org/zap"

	"github.com/qinzj/ums-ldap/internal/ldap/dn"
)

func (h *Handler) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() {
		_ = w.Write(resp)
	}()

	msg, err := r.GetSimpleBindMessage()
	if err != nil {
		h.logger.Error("failed to get bind message", zap.Error(err))
		return
	}

	bindDN := msg.UserName
	password := string(msg.Password)

	h.logger.Info("LDAP bind attempt", zap.String("dn", bindDN))

	// Extract username from DN
	username, err := dn.ExtractUsername(bindDN, h.cfg.BaseDN, h.cfg.Mode)
	if err != nil {
		h.logger.Warn("failed to extract username from DN",
			zap.String("dn", bindDN),
			zap.Error(err),
		)
		return
	}

	// Authenticate via service layer
	ctx := context.Background()
	_, err = h.userService.Authenticate(ctx, username, password)
	if err != nil {
		h.logger.Warn("LDAP bind failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return
	}

	h.logger.Info("LDAP bind success", zap.String("username", username))
	resp.SetResultCode(gldap.ResultSuccess)
}
