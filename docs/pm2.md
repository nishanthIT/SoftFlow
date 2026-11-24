# Run the existing application under PM2

Use `ecosystem.config.cjs` for the `auto-scan` application. It runs one foreground
supervisor, reloads application settings from `.env`, drains managed services on
restart, and limits repeated failed startups. The existing `cuckoo-api` PM2 entry
remains separate and is reused through the configured Cuckoo API.

The reported startup failure occurred after a successful frontend build: Next.js
inferred the home directory as its tracing root because of an unrelated parent
`package-lock.json`. It placed `server.js` below a nested path instead of the path
expected by the launcher. `outputFileTracingRoot` is now fixed to the frontend
directory. Production builds restore `tsconfig.json` and `next-env.d.ts` after
success, failure, or a handled interruption, so startup no longer leaves these
tracked files changed and blocks the next pull.

## One-time update from the old looping PM2 entry

After pushing the fixed application code, run as the existing application user:

```bash
cd ~/Auto_soft/SoftFlow
pm2 stop auto-scan
./stop.sh
git stash push -m "generated frontend files before PM2 fix" -- frontend/next-env.d.ts frontend/tsconfig.json
git pull --ff-only
pm2 delete auto-scan
pm2 start ecosystem.config.cjs --only auto-scan
pm2 save
pm2 logs auto-scan --lines 60 --nostream
```

The stash preserves only the two build-modified frontend files for inspection;
the fixed configuration is provided by the update. Leave that stash unapplied
unless it contains a deliberate setting you need to transfer. Database files,
sample storage and `.env` remain in the existing checkout. Only the `auto-scan`
PM2 entry is replaced; the separate `cuckoo-api` entry stays running.

Startup prints `[PM2] Application ready; foreground supervisor is running`
after the frontend proxy, backend and worker queues pass their checks. Inspect
`pm2 list` and the printed website URL. PM2's `online` label alone does not verify
application readiness; startup errors remain in the PM2 and `.local/logs/` logs.

## Later environment changes and code updates

Edit the existing `.env`, then:

```bash
pm2 restart auto-scan --update-env
pm2 logs auto-scan --lines 60 --nostream
```

After subsequent `git pull --ff-only` updates, use the same restart command.
Application keys present in `.env` take precedence over PM2's cached environment.
The launcher reuses an unchanged frontend release; source or API URL changes
produce a new build before application services are replaced. Required Cuckoo
readiness and existing approval checks remain enforced.

Use `pm2 stop auto-scan` for shutdown in this mode. It drains workers before
stopping their broker/database; PM2 is configured to signal the supervisor rather
than every descendant. If active work exceeds the application shutdown deadline,
its services and ownership records are retained for recovery. Avoid running a
second systemd supervisor for the same checkout.

Outside PM2, `./start` retains the existing background-service behavior.
`./start --foreground` selects the supervised foreground mode explicitly.

References: [Next.js standalone output](https://nextjs.org/docs/app/api-reference/config/next-config-js/output),
[PM2 graceful shutdown](https://pm2.keymetrics.io/docs/usage/signals-clean-restart/),
[PM2 restart strategies](https://pm2.keymetrics.io/docs/usage/restart-strategies/).
