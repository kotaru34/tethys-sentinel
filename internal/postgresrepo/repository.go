package postgresrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const SchemaVersion = 1

type Config struct {
	DSN                    string
	AllowInsecureTransport bool
	MaxConns               int32
}

type Repository struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, cfg Config) (*Repository, error) {
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	if poolCfg.ConnConfig.TLSConfig == nil && !cfg.AllowInsecureTransport {
		return nil, errors.New("PostgreSQL TLS with server verification is required")
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	} else if poolCfg.MaxConns > 16 {
		poolCfg.MaxConns = 16
	}
	poolCfg.MinConns = 0
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "tethys-sentinel-control"
	poolCfg.ConnConfig.RuntimeParams["statement_timeout"] = "5s"
	poolCfg.ConnConfig.RuntimeParams["lock_timeout"] = "2s"
	poolCfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "10s"

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	repo := &Repository{pool: pool}
	if err := repo.validate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return repo, nil
}

func (r *Repository) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}

func (r *Repository) validate(ctx context.Context) error {
	if r == nil || r.pool == nil {
		return errors.New("PostgreSQL repository is not initialized")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.pool.Ping(checkCtx); err != nil {
		return fmt.Errorf("ping PostgreSQL: %w", err)
	}

	var version int
	var canCreateSchema bool
	var ownerMember bool
	if err := r.pool.QueryRow(checkCtx, `
		SELECT
			(SELECT version FROM sentinel.schema_version WHERE id = 1),
			has_schema_privilege(current_user, 'sentinel', 'CREATE'),
			pg_has_role(current_user, 'sentinel_owner', 'MEMBER')
	`).Scan(&version, &canCreateSchema, &ownerMember); err != nil {
		return fmt.Errorf("validate Sentinel PostgreSQL schema: %w", err)
	}
	if version != SchemaVersion {
		return fmt.Errorf("unsupported Sentinel PostgreSQL schema version %d (want %d)", version, SchemaVersion)
	}
	if canCreateSchema {
		return errors.New("PostgreSQL runtime role unexpectedly has CREATE on sentinel schema")
	}
	if ownerMember {
		return errors.New("PostgreSQL runtime role must not be a member of sentinel_owner")
	}
	return nil
}
