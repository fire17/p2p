// src/browser/shim/globals.js — install the Node globals our shared protocol source expects.
//
// Import this FIRST (before any src/ module) — src/noise.js touches `Buffer` at module top level.
// See src/browser/p2p.js, where it is the first import for exactly that reason.
//
// Two globals, that's all:
//   Buffer   — src/{key,noise,wire,node,group}.js and src/rendezvous/tracker.js use it everywhere
//   process  — src/node.js reads `process.env.P2P_DEBUG` for its opt-in trace
//
// (`node:crypto` is handled separately, by the import map in index.html -> ./node-crypto.js.)

import { Buffer, assertSingleInstance } from './buffer.js'

// Fail fast if a relative import ever bypassed the import map and loaded a 2nd copy of buffer.js:
// the brand-based isBuffer keeps two copies INTEROPERATING, but a duplicate is a real import-hygiene
// bug that this catches loudly at startup instead of as a mysterious later key rejection.
assertSingleInstance()

if (typeof globalThis.Buffer === 'undefined') globalThis.Buffer = Buffer

// src/node.js: `process.env.P2P_DEBUG ? … : () => {}` — give it an env to read.
// Set P2P_DEBUG in the console (globalThis.process.env.P2P_DEBUG = '1') before listen() to trace
// first contact.
if (typeof globalThis.process === 'undefined') globalThis.process = { env: {} }

export { Buffer }
