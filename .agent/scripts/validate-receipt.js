#!/usr/bin/env node
// .agent/scripts/validate-receipt.js
// Zero-dependency JSON Schema (subset) validator for the .agent/ control plane.
// Deliberately hand-rolled instead of depending on ajv (a transitive, undeclared dependency of
// this repo) so the .agent/ contracts remain independently valid and cannot silently break if
// an unrelated package's dependency tree changes.
//
// Supports: type, enum, required, properties, items, minLength, maxLength.
// This is intentionally a subset of draft-07 — enough to gate receipts, not a general validator.
'use strict';

const fs = require('fs');
const path = require('path');

function typeOf(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  return typeof value;
}

function validate(schema, value, pointer, errors) {
  if (schema.type) {
    const actual = typeOf(value);
    const expected = schema.type;
    const ok = expected === 'number' ? (actual === 'number') : actual === expected;
    if (!ok) {
      errors.push(`${pointer}: expected type "${expected}", got "${actual}"`);
      return; // further checks would be noise once the type itself is wrong
    }
  }

  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${pointer}: value "${value}" not in enum [${schema.enum.join(', ')}]`);
  }

  if (typeof value === 'string') {
    if (typeof schema.minLength === 'number' && value.length < schema.minLength) {
      errors.push(`${pointer}: string shorter than minLength ${schema.minLength}`);
    }
    if (typeof schema.maxLength === 'number' && value.length > schema.maxLength) {
      errors.push(`${pointer}: string longer than maxLength ${schema.maxLength}`);
    }
  }

  if (schema.type === 'object' && value && typeof value === 'object') {
    for (const key of schema.required || []) {
      if (!(key in value)) {
        errors.push(`${pointer}: missing required property "${key}"`);
      }
    }
    const props = schema.properties || {};
    for (const [key, subSchema] of Object.entries(props)) {
      if (key in value) {
        validate(subSchema, value[key], `${pointer}.${key}`, errors);
      }
    }
  }

  if (schema.type === 'array' && Array.isArray(value) && schema.items) {
    value.forEach((item, i) => validate(schema.items, item, `${pointer}[${i}]`, errors));
  }
}

// SECURITY: never throws on malformed JSON. The previous version let JSON.parse's SyntaxError
// propagate uncaught all the way through release-warden.js's evaluate()/main(), which crashed the
// entire gate with no warden-receipt.json written at all and an exit code (1) that collided with
// the script's own documented meaning for BLOCK rather than FREEZE. A partial/interrupted write of
// any receipt this graph reads must fail closed with a recorded decision, not crash with none.
function validateReceipt(schemaPath, receiptPath) {
  let schema;
  try {
    schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  } catch (e) {
    return { valid: false, errors: [`schema at ${schemaPath} is not valid JSON: ${e.message}`], receipt: null };
  }
  let receipt;
  try {
    receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  } catch (e) {
    return { valid: false, errors: [`${receiptPath} is not valid JSON: ${e.message}`], receipt: null };
  }
  const errors = [];
  validate(schema, receipt, '$', errors);
  return { valid: errors.length === 0, errors, receipt };
}

function main() {
  const [, , schemaArg, receiptArg] = process.argv;
  if (!schemaArg || !receiptArg) {
    console.error('Usage: validate-receipt.js <schema-name|schema-path> <receipt-path>');
    process.exit(2);
  }
  const contractsDir = path.join(__dirname, '..', 'contracts');
  const schemaPath = fs.existsSync(schemaArg)
    ? schemaArg
    : path.join(contractsDir, schemaArg.endsWith('.schema.json') ? schemaArg : `${schemaArg}.schema.json`);

  if (!fs.existsSync(schemaPath)) {
    console.error(`FREEZE: schema not found: ${schemaPath}`);
    process.exit(2);
  }
  if (!fs.existsSync(receiptArg)) {
    console.error(`FREEZE: receipt not found: ${receiptArg}`);
    process.exit(2);
  }

  const { valid, errors } = validateReceipt(schemaPath, receiptArg);
  if (valid) {
    console.log(`VALID: ${receiptArg} conforms to ${path.basename(schemaPath)}`);
    process.exit(0);
  }
  console.error(`INVALID: ${receiptArg} does not conform to ${path.basename(schemaPath)}`);
  for (const err of errors) console.error(`  - ${err}`);
  process.exit(1);
}

if (require.main === module) {
  main();
}

module.exports = { validate, validateReceipt };
