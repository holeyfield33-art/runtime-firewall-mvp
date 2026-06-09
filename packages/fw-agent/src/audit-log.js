// packages/fw-agent/src/audit-log.js
// Persistent append-only forensic event writer with size-based log rotation.
// Writes structured JSON lines to HELIOS_LOG_DIR or falls back to a temp directory.

const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_LOG_DIR =
  process.env.HELIOS_LOG_DIR ||
  (process.platform !== 'win32' ? '/var/log/helios' : path.join(os.tmpdir(), 'helios'));

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB per rotation segment
const MAX_ROTATIONS = 5;

class AuditLog {
  constructor(logDir = DEFAULT_LOG_DIR) {
    this.logDir = logDir;
    this.logPath = null;
    this.fd = null;
    this._init();
  }

  _init() {
    // Try configured dir; fall back to system temp on permission errors
    for (const dir of [this.logDir, path.join(os.tmpdir(), 'helios')]) {
      try {
        fs.mkdirSync(dir, { recursive: true });
        this.logDir = dir;
        this.logPath = path.join(dir, 'audit.log');
        this.fd = fs.openSync(this.logPath, 'a');
        return;
      } catch (e) {
        // Try next fallback
      }
    }
    // All attempts failed - audit log disabled, events go to stderr only
    this.logPath = null;
  }

  _rotate() {
    if (!this.logPath) return;
    try {
      if (this.fd !== null) {
        fs.closeSync(this.fd);
        this.fd = null;
      }
      for (let i = MAX_ROTATIONS - 1; i >= 1; i--) {
        const src = `${this.logPath}.${i}`;
        const dst = `${this.logPath}.${i + 1}`;
        if (fs.existsSync(src)) {
          try { fs.renameSync(src, dst); } catch (e) {}
        }
      }
      try { fs.renameSync(this.logPath, `${this.logPath}.1`); } catch (e) {}
      this.fd = fs.openSync(this.logPath, 'a');
    } catch (e) {
      // If rotation fails, attempt a fresh open
      try { this.fd = fs.openSync(this.logPath, 'a'); } catch (e2) { this.fd = null; }
    }
  }

  write(event) {
    const line = JSON.stringify({ ...event, _logged_at: new Date().toISOString() }) + '\n';

    if (this.fd !== null) {
      try {
        const buf = Buffer.from(line, 'utf8');
        fs.writeSync(this.fd, buf);
        const stat = fs.fstatSync(this.fd);
        if (stat.size > MAX_FILE_SIZE) {
          this._rotate();
        }
      } catch (e) {
        process.stderr.write('[AuditLog] write error: ' + e.message + '\n');
      }
    } else {
      // Fallback: structured stderr so events aren't silently lost
      process.stderr.write('[HELIOS-AUDIT] ' + line);
    }
  }

  close() {
    if (this.fd !== null) {
      try { fs.closeSync(this.fd); } catch (e) {}
      this.fd = null;
    }
  }

  get filePath() {
    return this.logPath;
  }
}

let _instance = null;

function getAuditLog() {
  if (!_instance) _instance = new AuditLog();
  return _instance;
}

module.exports = { AuditLog, getAuditLog, DEFAULT_LOG_DIR };
