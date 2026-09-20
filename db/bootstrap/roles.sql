-- Tethys Sentinel PostgreSQL role bootstrap.
-- Run once as a PostgreSQL administrator before applying schema migrations.
-- This file deliberately creates NOLOGIN group roles only. Create deployment
-- and runtime LOGIN roles separately with locally managed credentials, then
-- grant the appropriate group role to each LOGIN.

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_owner') THEN
        CREATE ROLE sentinel_owner
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_migrator') THEN
        CREATE ROLE sentinel_migrator
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_control') THEN
        CREATE ROLE sentinel_control
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

-- Reassert attributes if the group roles already existed.
ALTER ROLE sentinel_owner
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinel_migrator
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinel_control
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;

-- A deployment LOGIN may be granted sentinel_migrator. The migrator can SET
-- ROLE sentinel_owner while applying reviewed migrations, but runtime cannot.
GRANT sentinel_owner TO sentinel_migrator;

-- Example only; do not commit actual LOGIN names/passwords:
--   CREATE ROLE sentinel_deploy LOGIN PASSWORD '...';
--   GRANT sentinel_migrator TO sentinel_deploy;
--   CREATE ROLE sentinel_control_login LOGIN PASSWORD '...';
--   GRANT sentinel_control TO sentinel_control_login;
