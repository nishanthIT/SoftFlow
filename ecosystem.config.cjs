// Only the application belongs to this entry. Keep your existing cuckoo-api
// PM2 process separate; the application reuses its configured API.
module.exports = {
  apps: [{
    name: 'auto-scan',
    cwd: __dirname,
    script: './start.sh',
    interpreter: 'bash',
    args: '--foreground',
    instances: 1,
    exec_mode: 'fork',
    watch: false,
    autorestart: true,
    stop_exit_codes: [0],
    min_uptime: '60s',
    max_restarts: 5,
    exp_backoff_restart_delay: 1000,
    // local.py drains workers before stopping their broker/database. Signal
    // only the foreground owner, never every descendant at once.
    treekill: false,
    kill_timeout: 900000,
  }],
};
