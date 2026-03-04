package dao

import (
	"context"

	"github.com/qinzj/ums-ldap/internal/ent"
)

// DAO provides data access operations.
type DAO struct {
	client *ent.Client
}

// New creates a new DAO instance.
func New(client *ent.Client) *DAO {
	return &DAO{client: client}
}

// Client returns the underlying Ent client.
func (d *DAO) Client() *ent.Client {
	return d.client
}

// AutoMigrate runs database schema migration.
func (d *DAO) AutoMigrate(ctx context.Context) error {
	return d.client.Schema.Create(ctx)
}
