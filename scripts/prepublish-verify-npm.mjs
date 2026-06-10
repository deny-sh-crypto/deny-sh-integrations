#!/usr/bin/env node
/**
 * prepublish-verify-npm.mjs — bulletproof pre-publish gate for npm packages.
 *
 * THE recurring deny.sh republish bug, killed: the `files` whitelist in
 * package.json is hand-maintained and drifts from the actual transitive import
 * graph. A relative `./x.js` import points at a file the whitelist forgot, npm
 * packs a tarball missing it, and the break is only caught by the POST-publish
 * fresh-install smoke (2.0.6 dist/src/decoy-engine, 2.2.1 dist/src/honey.js).
 * That forces a version bump + republish and desyncs the registries.
 *
 * This gate runs PRE-publish, needs no network, installs no deps, publishes
 * nothing:
 *   1. `npm pack` the package exactly as it would publish.
 *   2. Extract the real tarball file list.
 *   3. From every entrypoint (`main`, `module`, `bin`, every `exports` target),
 *      walk EVERY relative import/require/export-from specifier, recursively.
 *   4. Fail if any reachable relative module is NOT in the tarball, or if any
 *      declared entrypoint/exports target is missing.
 *
 * Catches 100% of the files-whitelist class deterministically. Exit 0 = safe to
 * publish; non-zero = DO NOT publish, fix the `files` array first.
 *
 * Usage: node prepublish-verify-npm.mjs <packageDir>
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync, existsSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve, relative, extname } from 'node:path';

const pkgDir = resolve(process.argv[2] || '.');
const fail = (msg) => { console.error(`\x1b[31m✗ prepublish-verify: ${msg}\x1b[0m`); process.exit(1); };
const ok = (msg) => console.log(`\x1b[32m✓\x1b[0m ${msg}`);

if (!existsSync(join(pkgDir, 'package.json'))) fail(`no package.json in ${pkgDir}`);
const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const pkgName = pkg.name ?? '(unnamed)';
console.log(`\n── prepublish-verify: ${pkgName}@${pkg.version} (${pkgDir}) ──`);

// 1. Pack the tarball exactly as npm publish would.
const work = mkdtempSync(join(tmpdir(), 'prepub-'));
// Force a REAL pack even when this gate runs inside `npm publish --dry-run`
// (which exports npm_config_dry_run=true to children, making `npm pack` list
// without writing a tarball). Strip every dry-run env knob so we always get a
// real .tgz to inspect.
const packEnv = { ...process.env };
for (const k of Object.keys(packEnv)) {
  if (/^npm_config_dry[_-]?run$/i.test(k)) delete packEnv[k];
}
packEnv.npm_config_dry_run = 'false';
let tarball;
try {
  const out = execFileSync('npm', ['pack', '--json', '--pack-destination', work], {
    cwd: pkgDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: packEnv,
  });
  // npm may prepend lifecycle noise; grab the JSON array from the output.
  const jsonStart = out.indexOf('[');
  const meta = JSON.parse(jsonStart >= 0 ? out.slice(jsonStart) : out);
  tarball = join(work, meta[0].filename);
} catch (e) {
  rmSync(work, { recursive: true, force: true });
  fail(`npm pack failed: ${e.message}`);
}
// If a dry-run env still suppressed the write, fall back to any .tgz in workdir.
if (!existsSync(tarball)) {
  const tgz = readdirSync(work).filter((f) => f.endsWith('.tgz'));
  if (tgz.length === 1) tarball = join(work, tgz[0]);
}
if (!existsSync(tarball)) {
  rmSync(work, { recursive: true, force: true });
  fail(`npm pack produced no tarball (dry-run env may have suppressed the write): ${tarball}`);
}

// 2. Extract + list the real shipped files (paths relative to package root,
//    tar strips the leading `package/`).
execFileSync('tar', ['-xzf', tarball, '-C', work], { stdio: 'ignore' });
const root = join(work, 'package');
const shipped = new Set();
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else shipped.add(relative(root, p));
  }
})(root);
ok(`packed ${shipped.size} files`);

// 3. Collect entrypoints: main, module, bin, and every exports target.
const entries = new Set();
const addEntry = (v) => { if (typeof v === 'string') entries.add(v.replace(/^\.\//, '')); };
addEntry(pkg.main);
addEntry(pkg.module);
addEntry(pkg.types);
if (typeof pkg.bin === 'string') addEntry(pkg.bin);
else if (pkg.bin && typeof pkg.bin === 'object') Object.values(pkg.bin).forEach(addEntry);
const collectExports = (node) => {
  if (typeof node === 'string') addEntry(node);
  else if (node && typeof node === 'object') Object.values(node).forEach(collectExports);
};
if (pkg.exports) collectExports(pkg.exports);
if (entries.size === 0) fail('no entrypoints found (main/module/bin/exports all empty)');

// Every declared entrypoint must itself be in the tarball.
for (const e of entries) {
  if (!shipped.has(e)) fail(`declared entrypoint/exports target NOT in tarball: ${e} (add to package.json "files")`);
}
ok(`${entries.size} entrypoints all present`);

// 4. Walk the relative-import graph from each .js/.mjs/.cjs entry.
const RELATIVE_IMPORT = /(?:import\s[^'"]*?from\s*|import\s*|export\s[^'"]*?from\s*|require\s*\(\s*|import\s*\(\s*)['"](\.[^'"]+)['"]/g;
const tried = new Set();
const missing = [];

function resolveSpecifier(fromFile, spec) {
  // Mirror Node ESM relative resolution against the tarball filesystem.
  const base = resolve(root, dirname(fromFile), spec);
  const rels = [];
  const asRel = (abs) => relative(root, abs);
  if (extname(spec)) {
    rels.push(asRel(base));
  } else {
    // Extensionless: try .js/.mjs/.cjs then index.* (bundler/TS-style).
    for (const ext of ['.js', '.mjs', '.cjs']) rels.push(asRel(base + ext));
    for (const ext of ['.js', '.mjs', '.cjs']) rels.push(asRel(join(base, `index${ext}`)));
  }
  return rels;
}

function walkFile(relFile) {
  if (tried.has(relFile)) return;
  tried.add(relFile);
  if (!/\.(js|mjs|cjs)$/.test(relFile)) return; // only follow JS module graph
  const abs = join(root, relFile);
  if (!shipped.has(relFile) || !existsSync(abs)) return; // missing reported by caller
  const src = readFileSync(abs, 'utf8');
  let m;
  while ((m = RELATIVE_IMPORT.exec(src)) !== null) {
    const spec = m[1];
    const candidates = resolveSpecifier(relFile, spec);
    const hit = candidates.find((c) => shipped.has(c));
    if (!hit) {
      missing.push({ from: relFile, spec, candidates });
    } else {
      walkFile(hit);
    }
  }
}

for (const e of entries) if (/\.(js|mjs|cjs)$/.test(e)) walkFile(e);

rmSync(work, { recursive: true, force: true });

if (missing.length) {
  console.error(`\x1b[31m\n✗ ${missing.length} relative import(s) resolve to files NOT in the tarball:\x1b[0m`);
  for (const x of missing) {
    console.error(`    ${x.from}  →  '${x.spec}'`);
    console.error(`      tried: ${x.candidates.join(', ')}`);
  }
  console.error(`\nFix: add the missing file(s) to package.json "files" (or the public template at scripts/public/package.json), then re-run. DO NOT publish.`);
  process.exit(1);
}
ok(`import graph complete: ${tried.size} modules, every relative import resolves inside the tarball`);
console.log(`\x1b[32m✓ ${pkgName}@${pkg.version} is safe to publish.\x1b[0m\n`);
