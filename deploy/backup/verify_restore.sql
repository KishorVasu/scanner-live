-- Checks a restored database (deploy/backup/restore.sh). Any failed check raises and psql exits non-zero.
\set ON_ERROR_STOP on
DO $$
DECLARE n int;
BEGIN
  IF (SELECT count(*) FROM alembic_version) <> 1 THEN RAISE EXCEPTION 'alembic_version missing'; END IF;
  SELECT count(*) INTO n FROM pg_trigger
   WHERE tgname IN ('trg_audit_logs_no_update_delete', 'trg_audit_logs_no_truncate') AND NOT tgisinternal;
  IF n <> 2 THEN RAISE EXCEPTION 'audit_logs append-only triggers missing (% of 2)', n; END IF;
  IF has_table_privilege('platform_app', 'audit_logs', 'UPDATE') OR has_table_privilege('platform_app', 'audit_logs', 'DELETE')
     OR has_table_privilege('platform_app', 'audit_logs', 'TRUNCATE') THEN
    RAISE EXCEPTION 'platform_app may modify audit_logs after restore';
  END IF;
  IF NOT has_table_privilege('platform_app', 'audit_logs', 'INSERT') THEN RAISE EXCEPTION 'app grants not restored'; END IF;
END $$;
SELECT version_num AS alembic_head FROM alembic_version;
SELECT 'users' AS t, count(*) FROM users UNION ALL SELECT 'projects', count(*) FROM projects
UNION ALL SELECT 'security_findings', count(*) FROM security_findings UNION ALL SELECT 'reports', count(*) FROM reports
UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs;
