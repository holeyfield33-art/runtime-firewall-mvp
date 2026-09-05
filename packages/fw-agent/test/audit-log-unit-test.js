// packages/fw-agent/test/audit-log-unit-test.js
// Unit tests for AuditLog: file writes, structured output, stderr fallback.
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { AuditLog } = require('../src/audit-log');

// ── Test 1: write event and verify file content ───────────────────────────────
{
  const testDir = path.join(os.tmpdir(), `helios-auditlog-test-${Date.now()}`);
  const log = new AuditLog(testDir);

  const eventTime = Date.now();
  log.write({ eventType: 'TEST_EVENT', packageName: 'test-pkg', timestamp: eventTime });
  log.close();

  assert.ok(log.filePath, 'AuditLog must have a file path after init');
  const content = fs.readFileSync(log.filePath, 'utf8').trim();
  const parsed = JSON.parse(content);

  assert.strictEqual(parsed.eventType, 'TEST_EVENT', 'eventType must be preserved');
  assert.strictEqual(parsed.packageName, 'test-pkg', 'packageName must be preserved');
  assert.strictEqual(parsed.timestamp, eventTime, 'timestamp must be preserved');
  assert.ok(parsed._logged_at, '_logged_at must be added automatically');

  try { fs.rmSync(testDir, { recursive: true }); } catch (e) {}
  console.log('  ✓ AuditLog writes structured JSON lines to file');
}

// ── Test 2: multiple writes produce multiple JSON lines ───────────────────────
{
  const testDir = path.join(os.tmpdir(), `helios-auditlog-test2-${Date.now()}`);
  const log = new AuditLog(testDir);

  log.write({ eventType: 'EVT_A', packageName: 'pkg-a', timestamp: 1 });
  log.write({ eventType: 'EVT_B', packageName: 'pkg-b', timestamp: 2 });
  log.write({ eventType: 'EVT_C', packageName: 'pkg-c', timestamp: 3 });
  log.close();

  const lines = fs.readFileSync(log.filePath, 'utf8').trim().split('\n');
  assert.strictEqual(lines.length, 3, 'Must produce one JSON line per write');

  const events = lines.map(l => JSON.parse(l));
  assert.strictEqual(events[0].eventType, 'EVT_A');
  assert.strictEqual(events[1].eventType, 'EVT_B');
  assert.strictEqual(events[2].eventType, 'EVT_C');

  try { fs.rmSync(testDir, { recursive: true }); } catch (e) {}
  console.log('  ✓ AuditLog produces one JSON line per write');
}

// ── Test 3: stderr fallback when file descriptor unavailable ─────────────────
{
  const testDir = path.join(os.tmpdir(), `helios-auditlog-test3-${Date.now()}`);
  const log = new AuditLog(testDir);
  log.close();

  // Force fallback path by nulling fd and logPath
  log.fd = null;
  log.logPath = null;

  let stderrCapture = '';
  const origWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (data) => { stderrCapture += String(data); return true; };

  log.write({ eventType: 'FALLBACK_EVENT', packageName: 'test', timestamp: Date.now() });

  process.stderr.write = origWrite;

  assert.ok(stderrCapture.includes('[HELIOS-AUDIT]'), 'Fallback must use [HELIOS-AUDIT] prefix');
  assert.ok(stderrCapture.includes('FALLBACK_EVENT'), 'Fallback must include event data');

  try { fs.rmSync(testDir, { recursive: true }); } catch (e) {}
  console.log('  ✓ AuditLog falls back to stderr when file unavailable');
}

// ── Test 4: F-6.2 (P1-3) — new audit files are created with restrictive 0600 permissions ──────
// POSIX only: Windows has no owner/group/other permission bits, so mode bits are not a
// meaningful assertion there ("0600 or equivalent supported behavior" per the finding).
if (process.platform !== 'win32') {
  const testDir = path.join(os.tmpdir(), `helios-auditlog-test4-${Date.now()}`);
  const log = new AuditLog(testDir);
  log.write({ eventType: 'PERM_TEST', timestamp: Date.now() });

  const mode = fs.statSync(log.filePath).mode & 0o777;
  assert.strictEqual(mode, 0o600, `audit.log must be created with mode 0600, got ${mode.toString(8)}`);

  log.close();
  try { fs.rmSync(testDir, { recursive: true }); } catch (e) {}
  console.log('  ✓ AuditLog creates new files with restrictive 0600 permissions (F-6.2)');
} else {
  console.log('  (skipped) 0600 permission check is POSIX-only; not meaningful on win32 (F-6.2)');
}

// ── Test 5: F-6.2 (P1-3) — rotation preserves the secure mode on the new active segment ───────
if (process.platform !== 'win32') {
  const testDir = path.join(os.tmpdir(), `helios-auditlog-test5-${Date.now()}`);
  const log = new AuditLog(testDir);
  log.write({ eventType: 'PRE_ROTATE', timestamp: Date.now() });

  // Loosen the pre-rotation file's mode to confirm rotation re-asserts 0600 on the NEW file
  // rather than merely inheriting whatever mode happened to be on disk beforehand.
  fs.chmodSync(log.filePath, 0o644);
  log._rotate();
  log.write({ eventType: 'POST_ROTATE', timestamp: Date.now() });

  const mode = fs.statSync(log.filePath).mode & 0o777;
  assert.strictEqual(mode, 0o600, `rotated-in audit.log must still be mode 0600, got ${mode.toString(8)}`);
  assert.ok(fs.existsSync(`${log.filePath}.1`), 'the rotated-out segment must exist at .1');

  // The rotated-out segment (.1) is the file that was loosened to 0644 above, renamed but
  // otherwise untouched -- it still contains real audit data, so it must be re-secured too, not
  // just the freshly-created active file.
  const rotatedMode = fs.statSync(`${log.filePath}.1`).mode & 0o777;
  assert.strictEqual(rotatedMode, 0o600, `rotated-out .1 segment must also be re-secured to 0600, got ${rotatedMode.toString(8)}`);

  log.close();
  try { fs.rmSync(testDir, { recursive: true }); } catch (e) {}
  console.log('  ✓ AuditLog rotation preserves the secure 0600 mode on both the new active segment and the rotated-out .1 segment (F-6.2)');
} else {
  console.log('  (skipped) rotation-mode check is POSIX-only; not meaningful on win32 (F-6.2)');
}

console.log('All audit-log unit tests passed.');
