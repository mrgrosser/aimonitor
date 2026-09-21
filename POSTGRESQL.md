# PostgreSQL deployment and migration

Version 0.11.0 uses PostgreSQL 17 for deployed data. Docker Compose starts the database, waits for its health check, and connects the application through a pool (12 connections by default). PostgreSQL has its own persistent `postgres-data` volume and no host-published port. The existing `claude-monitor-data` volume remains mounted for attachments and the old SQLite database.

All application stores use PostgreSQL: findings and retention markers, audit history, policies, cases and attachment metadata, alerts and delivery queues, reports, usage imports, Claude/Copilot/Purview analytics, directory snapshots, and saved provider views. Live mode refuses to start without PostgreSQL configuration. SQLite remains available only for offline demos/tests and as an import source.

## New deployment

1. Copy `.env.example` to `.env`, set a strong `POSTGRES_PASSWORD`, and configure the existing application credentials and providers. Keep `SESSION_SECRET` stable across updates.
2. Run `docker compose up -d --build`.
3. Check `/health` for version `0.11.0` and `database: postgresql`, then `/ready` for a successful database connection.

The database password is passed as a separate connection field, so URL encoding is not necessary for Compose. Follow your environment-file quoting rules for characters such as `$` and `#`. Do not change `POSTGRES_PASSWORD` on an existing database volume without also rotating the PostgreSQL role password.

## Existing deployment: retain SQLite data

Run these commands from the deployment checkout after updating the code. Use the SAME Compose project name and checkout location as before so the existing data volume is reused.

1. First set `POSTGRES_PASSWORD` in the existing `.env`, preserving the existing authentication settings and attachment path. The new Compose file requires it even for management commands. Then stop the old application so collection and user writes cannot continue during migration:

   ```sh
   docker compose stop claude-monitor
   ```

2. Keep the previous image for recovery, build the new image, and start only PostgreSQL:

   ```sh
   docker image tag claude-monitor:latest claude-monitor:pre-postgres
   docker compose build claude-monitor
   docker compose up -d postgres
   ```

3. Create a verified backup that includes any SQLite write-ahead log contents:

   ```sh
   docker compose run --rm --no-deps claude-monitor python -m tools.backup_sqlite --source /data/jo-ai-monitor.db --destination /data/jo-ai-monitor-before-postgres.db
   docker compose cp claude-monitor:/data/jo-ai-monitor-before-postgres.db ./jo-ai-monitor-before-postgres.db
   docker compose cp claude-monitor:/data/attachments ./attachments-before-postgres
   ```

   Adjust the last source path if you use a custom `ATTACHMENT_PATH`; skip it if no attachments exist. The backup command refuses to replace an existing backup; choose a new destination filename when repeating it. Keep an off-server copy until the PostgreSQL deployment has been validated.

4. Verify the SQLite source, then transfer it:

   ```sh
   docker compose run --rm --no-deps claude-monitor python -m tools.migrate_sqlite_to_postgres --source /data/jo-ai-monitor.db --check-only
   docker compose run --rm claude-monitor python -m tools.migrate_sqlite_to_postgres --source /data/jo-ai-monitor.db
   ```

   The migration checks SQLite integrity, foreign keys, and the audit hash chain. It reads a consistent, read-only snapshot, copies all source tables in dependency order, verifies row counts and every copied value, and advances generated-ID sequences. The transferred rows commit together only after verification. Unknown tables/columns and nonempty destinations are rejected. Failed transfers roll back their data; empty initialized tables may remain and a retry is supported. A completed migration cannot be rerun over existing data.

   Attachments stay in `/data/attachments` (or your configured `ATTACHMENT_PATH`); their database metadata and filenames are preserved. The source SQLite file is never modified or deleted. Migration requires a fresh PostgreSQL application database: do not start the application first.

5. Start the application and verify retained history:

   ```sh
   docker compose up -d claude-monitor
   ```

   Confirm `/ready` succeeds and `/health` shows PostgreSQL and `0.11.0`. Sign in, check historical usage periods, findings, case comments/attachments, and audit history. Restart the application once and confirm the same records remain available.

If the old SQLite file is present but no successful migration marker exists, application startup stops with a migration instruction. This prevents an accidental empty deployment. Do not remove the old volume to bypass this check.

## Managed PostgreSQL / non-Compose deployment

Set `DATABASE_URL` to your PostgreSQL URL (including your provider's TLS options), or supply `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, and `PGSSLMODE`. With URL configuration, percent-encode credential characters as required. Run the migration command before starting the application if transferring existing data. `DATABASE_POOL_SIZE` sets the per-process maximum; allow enough database connections for each process plus migration/administration.

The supplied Compose file deliberately uses its local `postgres` service and clears `DATABASE_URL`. To use a managed service, supply an explicit Compose override or deploy the application independently; do not leave contradictory connection settings.

## Backups and recovery

Use PostgreSQL backups after cutover. This creates a custom-format archive inside the database container and copies it to the current directory, avoiding shell binary redirection:

```sh
docker compose exec postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f /tmp/jo-ai-monitor.dump'
docker compose cp postgres:/tmp/jo-ai-monitor.dump ./jo-ai-monitor.dump
```

Back up the attachment volume alongside the database. Test `pg_restore` into a separate, empty recovery database before relying on a backup. Do not use `docker compose down -v` for routine updates: it removes database and attachment volumes.

For rollback before accepting new writes, stop the new application and restore the previous image with its preserved SQLite volume and previous deployment configuration. PostgreSQL changes made after cutover are not written back into SQLite; rolling back after new writes requires a separate reconciliation plan.

## Validation

The normal regression suite runs with `python -m unittest discover -s tests -q`. Set `TEST_POSTGRES_URL` to a disposable PostgreSQL test server to also run real database integration tests and live-startup checks. Integration tests create and remove uniquely named schemas. The CI PostgreSQL job exercises migration, transaction rollback, concurrent audit writers, persistence, and established application workflows.

Connection pooling follows the [Psycopg pool documentation](https://www.psycopg.org/psycopg3/docs/advanced/pool.html); cross-process audit/queue locking uses [PostgreSQL transaction advisory locks](https://www.postgresql.org/docs/17/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS).
