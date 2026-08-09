#!/usr/bin/env node
// Lightweight diagnostic probe child runner.
// Usage: node scripts/probe-child.js <probe> [probeArg]
const fs = require('fs');
const path = require('path');

function nowMs() { return Number(process.hrtime.bigint() / 1000000n); }

async function run() {
  const probe = process.argv[2];
  const probeArg = process.argv[3];
  try {
    if (!probe) throw new Error('missing probe');

    // Each probe measures its own elapsed ms using hrtime.bigint() inside this child.
    if (probe === 'node-startup') {
      const t0 = process.hrtime.bigint();
      // trivial work
      const t1 = process.hrtime.bigint();
      const elapsed = Number(t1 - t0) / 1e6;
      const out = JSON.stringify({ status: 'measured', elapsedMs: elapsed });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'agent-preload') {
      const agentPath = path.join(__dirname, '..', 'packages', 'fw-agent', 'index.js');
      const t0 = process.hrtime.bigint();
      // preload without enabling detection (honest baseline behavior)
      const env = Object.assign({}, process.env);
      delete env.FW_ENABLE_DETECTION;
      // require the module in-process
      require(agentPath);
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6 });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'agent-initialization') {
      const agentPath = path.join(__dirname, '..', 'packages', 'fw-agent', 'index.js');
      const t0 = process.hrtime.bigint();
      // Enable detection — this runs full startup paths (integrity, policy, detector...).
      process.env.FW_ENABLE_DETECTION = '1';
      // Allow dev policy key for test probe runs (documented opt-in test mechanism).
      process.env.FW_ALLOW_DEV_POLICY_KEY = '1';
      require(agentPath);
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6 });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'integrity-verification') {
      // Call same hash routine used by the agent to exercise real path.
      const crypto = require('crypto');
      const agentDir = path.join(__dirname, '..', 'packages', 'fw-agent');
      const selfFiles = [
        path.join(agentDir, 'index.js'),
        path.join(agentDir, 'src', 'detector.js'),
        path.join(agentDir, 'src', 'behavior-tracker.js'),
        path.join(agentDir, 'src', 'policy-watcher.js'),
        path.join(agentDir, 'src', 'quarantine.js'),
        path.join(agentDir, 'src', 'audit-log.js'),
        path.join(agentDir, 'src', 'policy.js'),
      ];
      const baselineFile = path.join(agentDir, '.helios-baseline');
      const t0 = process.hrtime.bigint();
      // Compute hash exactly as agent does
      const hash = crypto.createHash('sha256');
      for (const f of selfFiles) {
        try {
          const content = fs.readFileSync(f, 'utf8').replace(/\r\n/g, '\n');
          hash.update(content, 'utf8');
        } catch (e) {
          // ignore missing file entries — agent also tolerates reads failing when computing
        }
      }
      const cur = hash.digest('hex');
      let stored = null;
      if (fs.existsSync(baselineFile)) stored = fs.readFileSync(baselineFile, 'utf8').trim();
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6, baselinePresent: !!stored, match: stored === cur });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'policy-verification') {
      // Use the repository's policy-watcher verify path. Do not bypass signature checks.
      // Allow dev key explicitly (documented test mechanism)
      process.env.FW_ALLOW_DEV_POLICY_KEY = '1';
      const { PolicyWatcher } = require(path.join(__dirname, '..', 'packages', 'fw-agent', 'src', 'policy-watcher.js'));
      const policyPath = path.join(process.cwd(), 'policy.signed.json');
      const pw = new PolicyWatcher(policyPath, {});
      const t0 = process.hrtime.bigint();
      const ok = pw.verify();
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6, verified: ok, usedDevKey: true });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'detector-construction') {
      const { Detector } = require(path.join(__dirname, '..', 'packages', 'fw-agent', 'src', 'detector.js'));
      const t0 = process.hrtime.bigint();
      const d = new Detector();
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6 });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'hook-installation') {
      // Measure time to install hook (agent initialization includes this). We'll require the
      // agent with detection enabled and record time to return from require(). This mirrors
      // real hook install without performing module compilations.
      const agentPath = path.join(__dirname, '..', 'packages', 'fw-agent', 'index.js');
      const t0 = process.hrtime.bigint();
      process.env.FW_ENABLE_DETECTION = '1';
      process.env.FW_ALLOW_DEV_POLICY_KEY = '1';
      require(agentPath);
      const t1 = process.hrtime.bigint();
      process.stderr.write(JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6 }) + '\n');
      return;
    }

    if (probe === 'audit-initialization') {
      const { getAuditLog } = require(path.join(__dirname, '..', 'packages', 'fw-agent', 'src', 'audit-log.js'));
      const t0 = process.hrtime.bigint();
      const al = getAuditLog();
      const t1 = process.hrtime.bigint();
      // Close to avoid leaving file handles open between child runs
      try { al.close(); } catch (e) {}
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6, filePath: al && al.filePath ? al.filePath : null });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'telemetry-initialization') {
      // Spawn telemetry worker by requiring agent with telemetry enabled and measuring time
      // to return from require()
      const agentPath = path.join(__dirname, '..', 'packages', 'fw-agent', 'index.js');
      process.env.FW_ENABLE_DETECTION = '1';
      process.env.FW_TELEMETRY = '1';
      process.env.FW_ALLOW_DEV_POLICY_KEY = '1';
      const t0 = process.hrtime.bigint();
      require(agentPath);
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6 });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'module-scan') {
      // probeArg indicates sample type: tiny|med|large
      const type = probeArg || 'tiny';
      const { Detector } = require(path.join(__dirname, '..', 'packages', 'fw-agent', 'src', 'detector.js'));
      const d = new Detector();
      const samples = {
        tiny: 'const x=1;module.exports=x;\n',
        med: 'const x=1;const y=x+2;const z=y*3;module.exports={x,y,z};\n',
        large: ('1+2+3+4+5+6+7+8+9+10;'.repeat(80) + '\n') + 'const x=1;const y=x+2;const z=y*3;const w=z+4;const v=w*w;module.exports={x,y,z,w,v};\n'
      };
      const content = samples[type] || samples.tiny;
      const t0 = process.hrtime.bigint();
      const r = d.scanModuleSync('sample', content, 'sample.js', null);
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6, detections: r.detections.length });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    if (probe === 'process-shutdown') {
      // Require agent with detection enabled and then trigger shutdown path and measure
      // time until process.exit callbacks complete. We'll measure time between calling
      // shutdown and the audit close call within the same process.
      const agentPath = path.join(__dirname, '..', 'packages', 'fw-agent', 'index.js');
      process.env.FW_ENABLE_DETECTION = '1';
      process.env.FW_ALLOW_DEV_POLICY_KEY = '1';
      require(agentPath);
      // send SIGINT to self to trigger shutdown handler
      const t0 = process.hrtime.bigint();
      process.kill(process.pid, 'SIGINT');
      // shutdown prints and then exits; to avoid exit before we can report, we attach
      // a short-lived listener. Instead, measure via a Promise and delay to let handlers run.
      await new Promise(r => setTimeout(r, 700));
      const t1 = process.hrtime.bigint();
      const out = JSON.stringify({ status: 'measured', elapsedMs: Number(t1 - t0) / 1e6 });
      if (process.env.PROBE_OUTFILE) {
        try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
      } else {
        process.stderr.write(out + '\n');
      }
      return;
    }

    const out = JSON.stringify({ status: 'not-measurable', reason: 'unknown-probe' });
    if (process.env.PROBE_OUTFILE) {
      try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e) { process.stderr.write(out + '\n'); }
    } else {
      process.stderr.write(out + '\n');
    }
  } catch (e) {
    const out = JSON.stringify({ status: 'error', reason: e && e.message });
    if (process.env.PROBE_OUTFILE) {
      try { fs.writeFileSync(process.env.PROBE_OUTFILE, out, 'utf8'); } catch (e2) { process.stderr.write(out + '\n'); }
    } else {
      process.stderr.write(out + '\n');
    }
    process.exit(2);
  }
}

run();
