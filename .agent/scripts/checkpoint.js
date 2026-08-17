#!/usr/bin/env node
// .agent/scripts/checkpoint.js
// Records git state (HEAD sha + working-tree cleanliness) into a run's checkpoints.json.
// This is the provenance backbone of the graph: Agent 2 must verify the exact sha Agent 1
// recorded, and the Release Warden must FREEZE if that sha moved during verification.
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function currentGitState(cwd) {
  const sha = git(['rev-parse', 'HEAD'], cwd);
  const status = git(['status', '--porcelain'], cwd);
  const branch = git(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
  return { sha, branch, dirty: status.length > 0, status };
}

function readCheckpoints(runDir) {
  const file = path.join(runDir, 'checkpoints.json');
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeCheckpoints(runDir, checkpoints) {
  fs.mkdirSync(runDir, { recursive: true });
  fs.writeFileSync(path.join(runDir, 'checkpoints.json'), JSON.stringify(checkpoints, null, 2) + '\n');
}

function create(runDir, label, cwd) {
  const state = currentGitState(cwd);
  const checkpoints = readCheckpoints(runDir);
  const entry = { label, timestamp: new Date().toISOString(), ...state };
  checkpoints.push(entry);
  writeCheckpoints(runDir, checkpoints);
  console.log(JSON.stringify(entry, null, 2));
  return entry;
}

function assertSha(runDir, expectedSha, cwd) {
  const state = currentGitState(cwd);
  const shortExpected = expectedSha.slice(0, state.sha.length);
  if (state.sha !== expectedSha && !state.sha.startsWith(expectedSha) && !expectedSha.startsWith(state.sha)) {
    console.error(`FREEZE: candidate SHA mismatch. expected=${expectedSha} actual=${state.sha}`);
    process.exit(2);
  }
  console.log(`OK: HEAD matches expected candidate SHA (${state.sha})`);
  return state;
}

function main() {
  const [, , cmd, runDir, ...rest] = process.argv;
  const cwd = process.cwd();
  if (cmd === 'create') {
    const [label] = rest;
    if (!runDir || !label) {
      console.error('Usage: checkpoint.js create <runDir> <label>');
      process.exit(2);
    }
    create(runDir, label, cwd);
  } else if (cmd === 'assert-sha') {
    const [expectedSha] = rest;
    if (!runDir || !expectedSha) {
      console.error('Usage: checkpoint.js assert-sha <runDir> <expectedSha>');
      process.exit(2);
    }
    assertSha(runDir, expectedSha, cwd);
  } else {
    console.error('Usage: checkpoint.js <create|assert-sha> <runDir> ...');
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = { currentGitState, create, assertSha, readCheckpoints };
