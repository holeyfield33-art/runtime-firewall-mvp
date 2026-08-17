#!/usr/bin/env node
// .agent/scripts/model-runner.js
// Thin Ollama client — the ONLY model-interface code in this prototype. Deliberately not an
// abstraction layer (no provider interface, no MRN integration): that generalization belongs in
// MRN's own ModelProvider when MRN eventually becomes the orchestrator (see .agent/README.md).
//
// This script does not run automatically as part of any gate. It exists so an agent role
// (boundary-engineer / red-team-verifier / release-warden's prose fields) can optionally be
// driven by a local model instead of a human/coding-agent typing the receipt by hand. Whether or
// not this script is used, the receipts it helps produce still go through the same schema
// validation and the same deterministic release-warden.js gate — the model is never trusted.
'use strict';

const DEFAULT_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';

async function isAvailable(host = DEFAULT_HOST) {
  try {
    const res = await fetch(`${host}/api/tags`, { method: 'GET' });
    return res.ok;
  } catch (e) {
    return false;
  }
}

async function generate({ model, prompt, host = DEFAULT_HOST, system }) {
  const res = await fetch(`${host}/api/generate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, prompt, system, stream: false }),
  });
  if (!res.ok) {
    throw new Error(`Ollama request failed: ${res.status} ${res.statusText}`);
  }
  const body = await res.json();
  return body.response;
}

async function main() {
  const [, , model, ...promptParts] = process.argv;
  if (!model || promptParts.length === 0) {
    console.error('Usage: model-runner.js <model> <prompt...>');
    process.exit(2);
  }
  const available = await isAvailable();
  if (!available) {
    // Per directive section 7 ("Infrastructure: model unavailable"): this is a FREEZE-worthy
    // condition for any run that depends on this script, not a silent fallback.
    console.error(`FREEZE: Ollama not reachable at ${DEFAULT_HOST}`);
    process.exit(2);
  }
  const response = await generate({ model, prompt: promptParts.join(' ') });
  console.log(response);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`FREEZE: model-runner error: ${err.message}`);
    process.exit(2);
  });
}

module.exports = { isAvailable, generate, DEFAULT_HOST };
