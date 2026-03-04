package ldap

import (
	"context"
	"strings"

	"github.com/jimlambrt/gldap"
	"go.uber.org/zap"

	"github.com/qinzj/ums-ldap/internal/ldap/filter"
)

func (h *Handler) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer func() {
		_ = w.Write(resp)
	}()

	msg, err := r.GetSearchMessage()
	if err != nil {
		h.logger.Error("failed to get search message", zap.Error(err))
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}

	h.logger.Info("LDAP search",
		zap.String("baseDN", msg.BaseDN),
		zap.String("filter", msg.Filter),
		zap.Int64("scope", int64(msg.Scope)),
		zap.Int64("sizeLimit", int64(msg.SizeLimit)),
	)

	ctx := context.Background()

	// Parse filter to determine what to search for
	var f *filter.Filter
	if msg.Filter != "" && msg.Filter != "(objectClass=*)" {
		f, err = filter.Parse(msg.Filter)
		if err != nil {
			h.logger.Warn("failed to parse filter", zap.String("filter", msg.Filter), zap.Error(err))
			resp.SetResultCode(gldap.ResultProtocolError)
			return
		}
	}

	// Determine search targets based on filter and baseDN
	searchUsers := true
	searchGroups := true

	if f != nil {
		oc := extractObjectClass(f)
		if oc != "" {
			searchUsers = isUserObjectClass(oc, h.cfg.Mode)
			searchGroups = isGroupObjectClass(oc, h.cfg.Mode)
		}
	}

	var entries []*ldapEntry
	count := 0
	limit := int(msg.SizeLimit)

	if searchUsers {
		users, err := h.userService.AllUsers(ctx)
		if err != nil {
			h.logger.Error("failed to query users", zap.Error(err))
			resp.SetResultCode(gldap.ResultOther)
			return
		}
		for _, u := range users {
			entry := h.userToEntry(u)
			if f == nil || matchEntry(f, entry) {
				entries = append(entries, entry)
				count++
				if limit > 0 && count >= limit {
					break
				}
			}
		}
	}

	if searchGroups && (limit == 0 || count < limit) {
		groups, err := h.groupService.AllGroups(ctx)
		if err != nil {
			h.logger.Error("failed to query groups", zap.Error(err))
			resp.SetResultCode(gldap.ResultOther)
			return
		}
		for _, g := range groups {
			entry := h.groupToEntry(g)
			if f == nil || matchEntry(f, entry) {
				entries = append(entries, entry)
				count++
				if limit > 0 && count >= limit {
					break
				}
			}
		}
	}

	// Write entries
	for _, entry := range entries {
		filteredAttrs := filterAttributes(entry.attrs, msg.Attributes)
		e := r.NewSearchResponseEntry(entry.dn, gldap.WithAttributes(filteredAttrs))
		_ = w.Write(e)
	}

	resp.SetResultCode(gldap.ResultSuccess)
	h.logger.Info("LDAP search completed", zap.Int("results", len(entries)))
}

// matchEntry evaluates a filter against an LDAP entry's attributes (in-memory matching).
func matchEntry(f *filter.Filter, entry *ldapEntry) bool {
	switch f.Type {
	case filter.FilterEqual:
		return matchEqual(f.Attr, f.Value, entry)
	case filter.FilterPresent:
		_, ok := entry.attrs[f.Attr]
		return ok
	case filter.FilterSubstring:
		return matchSubstring(f.Attr, f.Substr, entry)
	case filter.FilterGreaterOrEqual:
		vals := entry.attrs[f.Attr]
		for _, v := range vals {
			if v >= f.Value {
				return true
			}
		}
		return false
	case filter.FilterLessOrEqual:
		vals := entry.attrs[f.Attr]
		for _, v := range vals {
			if v <= f.Value {
				return true
			}
		}
		return false
	case filter.FilterApproxMatch:
		return matchEqual(f.Attr, f.Value, entry) // degrade to case-insensitive
	case filter.FilterAnd:
		for _, child := range f.Children {
			if !matchEntry(child, entry) {
				return false
			}
		}
		return true
	case filter.FilterOr:
		for _, child := range f.Children {
			if matchEntry(child, entry) {
				return true
			}
		}
		return false
	case filter.FilterNot:
		if len(f.Children) > 0 {
			return !matchEntry(f.Children[0], entry)
		}
		return false
	default:
		return false
	}
}

func matchEqual(attr, value string, entry *ldapEntry) bool {
	vals, ok := entry.attrs[attr]
	if !ok {
		return false
	}
	for _, v := range vals {
		if equalFold(v, value) {
			return true
		}
	}
	return false
}

func matchSubstring(attr string, substr *filter.SubstringFilter, entry *ldapEntry) bool {
	if substr == nil {
		return false
	}
	vals, ok := entry.attrs[attr]
	if !ok {
		return false
	}

	for _, v := range vals {
		lv := strings.ToLower(v)
		match := true

		remaining := lv

		if substr.Initial != "" {
			prefix := strings.ToLower(substr.Initial)
			if !strings.HasPrefix(remaining, prefix) {
				match = false
			} else {
				remaining = remaining[len(prefix):]
			}
		}

		if match {
			for _, any := range substr.Any {
				part := strings.ToLower(any)
				idx := strings.Index(remaining, part)
				if idx < 0 {
					match = false
					break
				}
				remaining = remaining[idx+len(part):]
			}
		}

		if match && substr.Final != "" {
			suffix := strings.ToLower(substr.Final)
			if !strings.HasSuffix(remaining, suffix) {
				match = false
			}
		}

		if match {
			return true
		}
	}
	return false
}

func extractObjectClass(f *filter.Filter) string {
	if f.Type == filter.FilterEqual && equalFold(f.Attr, "objectClass") {
		return f.Value
	}
	if f.Type == filter.FilterAnd || f.Type == filter.FilterOr {
		for _, child := range f.Children {
			if oc := extractObjectClass(child); oc != "" {
				return oc
			}
		}
	}
	return ""
}

func isUserObjectClass(oc, mode string) bool {
	switch mode {
	case "activedirectory":
		return equalFold(oc, "user") || equalFold(oc, "person") || equalFold(oc, "organizationalPerson")
	default: // openldap
		return equalFold(oc, "inetOrgPerson") || equalFold(oc, "person") || equalFold(oc, "organizationalPerson")
	}
}

func isGroupObjectClass(oc, mode string) bool {
	switch mode {
	case "activedirectory":
		return equalFold(oc, "group")
	default: // openldap
		return equalFold(oc, "groupOfNames")
	}
}

func filterAttributes(allAttrs map[string][]string, requested []string) map[string][]string {
	if len(requested) == 0 {
		return allAttrs
	}

	filtered := make(map[string][]string, len(requested))
	for _, attr := range requested {
		if vals, ok := allAttrs[attr]; ok {
			filtered[attr] = vals
		}
	}
	return filtered
}
