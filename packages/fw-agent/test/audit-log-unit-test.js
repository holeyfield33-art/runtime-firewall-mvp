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

console.log('All audit-log unit tests passed.');
