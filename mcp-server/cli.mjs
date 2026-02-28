#!/usr/bin/env node
/**
 * AgentAudit CLI — Security scanner for AI packages
 * 
 * Usage:
 *   agentaudit                                     Discover local MCP servers
 *   agentaudit discover [--quick|--deep]            Find MCP servers in AI editors
 *   agentaudit scan <repo-url> [--deep]             Quick scan (or deep audit with --deep)
 *   agentaudit audit <repo-url> [--verify self]     Deep LLM-powered security audit (verification enabled by default)
 *   agentaudit lookup <name>                        Look up package in registry
 *   agentaudit setup                                Register + configure API key
 * 
 * Global flags: --json, --quiet, --no-color, --verify, --timeout
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { createInterface } from 'readline';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_DIR = path.resolve(__dirname);
const REGISTRY_URL = 'https://agentaudit.dev';

// ── Global flags (set in main before command routing) ────
let jsonMode = false;
let quietMode = false;

// ── ANSI Colors (respects NO_COLOR and --no-color) ───────

const noColor = !!(process.env.NO_COLOR || process.argv.includes('--no-color'));

const c = noColor ? {
  reset: '', bold: '', dim: '', red: '', green: '', yellow: '',
  blue: '', magenta: '', cyan: '', white: '', gray: '',
  bgRed: '', bgGreen: '', bgYellow: '',
} : {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

const icons = {
  safe: `${c.green}✔${c.reset}`,
  caution: `${c.yellow}⚠${c.reset}`,
  unsafe: `${c.red}✖${c.reset}`,
  info: `${c.blue}ℹ${c.reset}`,
  scan: `${c.cyan}◉${c.reset}`,
  tree: `${c.gray}├──${c.reset}`,
  treeLast: `${c.gray}└──${c.reset}`,
  pipe: `${c.gray}│${c.reset}`,
  bullet: `${c.gray}•${c.reset}`,
};

// ── Credentials ─────────────────────────────────────────

const home = process.env.HOME || process.env.USERPROFILE || '';
const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
const USER_CRED_DIR = path.join(xdgConfig, 'agentaudit');
const USER_CRED_FILE = path.join(USER_CRED_DIR, 'credentials.json');
const SKILL_CRED_FILE = path.join(SKILL_DIR, 'config', 'credentials.json');

function loadCredentials() {
  for (const f of [SKILL_CRED_FILE, USER_CRED_FILE]) {
    if (fs.existsSync(f)) {
      try {
        const data = JSON.parse(fs.readFileSync(f, 'utf8'));
        if (data.api_key) return data;
      } catch {}
    }
  }
  if (process.env.AGENTAUDIT_API_KEY) {
    return { api_key: process.env.AGENTAUDIT_API_KEY, agent_name: 'env' };
  }
  return null;
}

function saveCredentials(data) {
  const json = JSON.stringify(data, null, 2);
  fs.mkdirSync(USER_CRED_DIR, { recursive: true });
  fs.writeFileSync(USER_CRED_FILE, json, { mode: 0o600 });
  try {
    fs.mkdirSync(path.dirname(SKILL_CRED_FILE), { recursive: true });
    fs.writeFileSync(SKILL_CRED_FILE, json, { mode: 0o600 });
  } catch {}
}

function askQuestion(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

/**
 * Interactive multi-select in terminal. No dependencies.
 * items: [{ label, sublabel?, value, checked? }]
 * Returns: array of selected values
 */
function multiSelect(items, { title = 'Select items', hint = 'Space=toggle  ↑↓=move  a=all  n=none  Enter=confirm' } = {}) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      // Non-interactive: return all items
      resolve(items.map(i => i.value));
      return;
    }
    
    const selected = new Set(items.filter(i => i.checked).map((_, idx) => idx));
    let cursor = 0;
    
    const render = () => {
      // Move cursor up to overwrite previous render
      process.stdout.write(`\x1b[${items.length + 3}A\x1b[J`);
      draw();
    };
    
    const draw = () => {
      console.log(`  ${c.bold}${title}${c.reset}  ${c.dim}(${selected.size}/${items.length} selected)${c.reset}`);
      console.log(`  ${c.dim}${hint}${c.reset}`);
      console.log();
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const isCursor = i === cursor;
        const isSelected = selected.has(i);
        const pointer = isCursor ? `${c.cyan}❯${c.reset}` : ' ';
        const checkbox = isSelected ? `${c.green}◉${c.reset}` : `${c.dim}○${c.reset}`;
        const label = isCursor ? `${c.bold}${item.label}${c.reset}` : item.label;
        const sub = item.sublabel ? `  ${c.dim}${item.sublabel}${c.reset}` : '';
        console.log(` ${pointer} ${checkbox}  ${label}${sub}`);
      }
    };
    
    // Initial draw
    draw();
    
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    
    const onData = (key) => {
      // Ctrl+C
      if (key === '\x03') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener('data', onData);
        console.log();
        process.exitCode = 0; return;
      }
      
      // Enter
      if (key === '\r' || key === '\n') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener('data', onData);
        resolve(items.filter((_, i) => selected.has(i)).map(i => i.value));
        return;
      }
      
      // Space — toggle
      if (key === ' ') {
        if (selected.has(cursor)) selected.delete(cursor);
        else selected.add(cursor);
        render();
        return;
      }
      
      // a — select all
      if (key === 'a') {
        for (let i = 0; i < items.length; i++) selected.add(i);
        render();
        return;
      }
      
      // n — select none
      if (key === 'n') {
        selected.clear();
        render();
        return;
      }
      
      // Arrow up / k
      if (key === '\x1b[A' || key === 'k') {
        cursor = (cursor - 1 + items.length) % items.length;
        render();
        return;
      }
      
      // Arrow down / j
      if (key === '\x1b[B' || key === 'j') {
        cursor = (cursor + 1) % items.length;
        render();
        return;
      }
    };
    
    process.stdin.on('data', onData);
  });
}

async function registerAgent(agentName) {
  const res = await fetch(`${REGISTRY_URL}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_name: agentName }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`Registration failed (HTTP ${res.status}): ${await res.text()}`);
  return res.json();
}

async function setupCommand() {
  console.log(`  ${c.bold}Setup${c.reset}`);
  console.log();

  const existing = loadCredentials();
  if (existing) {
    console.log(`  ${icons.safe}  Already configured as ${c.bold}${existing.agent_name}${c.reset}`);
    console.log(`  ${c.dim}Key: ${existing.api_key.slice(0, 8)}...${c.reset}`);
    console.log();
    const answer = await askQuestion(`  Reconfigure? ${c.dim}(y/N)${c.reset} `);
    if (answer.toLowerCase() !== 'y') {
      console.log(`  ${c.dim}Keeping existing config.${c.reset}`);
      return;
    }
    console.log();
  }

  console.log(`  ${c.bold}1)${c.reset} Register new agent ${c.dim}(free, creates API key automatically)${c.reset}`);
  console.log(`  ${c.bold}2)${c.reset} Enter existing API key`);
  console.log();
  const choice = await askQuestion(`  Choice ${c.dim}(1/2)${c.reset}: `);
  console.log();

  if (choice === '2') {
    const key = await askQuestion(`  API Key: `);
    if (!key) { console.log(`  ${c.red}No key entered.${c.reset}`); return; }
    const name = await askQuestion(`  Agent name ${c.dim}(optional)${c.reset}: `);
    saveCredentials({ api_key: key, agent_name: name || 'custom' });
    console.log();
    console.log(`  ${icons.safe}  Saved! Key stored in ${c.dim}${USER_CRED_FILE}${c.reset}`);
  } else {
    const name = await askQuestion(`  Agent name ${c.dim}(e.g. my-scanner, claude-desktop)${c.reset}: `);
    if (!name || !/^[a-zA-Z0-9._-]{2,64}$/.test(name)) {
      console.log(`  ${c.red}Invalid name. Use 2-64 chars: letters, numbers, dash, underscore, dot.${c.reset}`);
      return;
    }
    process.stdout.write(`  Registering ${c.bold}${name}${c.reset}...`);
    try {
      const data = await registerAgent(name);
      saveCredentials({ api_key: data.api_key, agent_name: data.agent_name });
      console.log(` ${c.green}done!${c.reset}`);
      console.log();
      console.log(`  ${icons.safe}  Registered as ${c.bold}${data.agent_name}${c.reset}`);
      console.log(`  ${c.dim}Key: ${data.api_key.slice(0, 12)}...${c.reset}`);
      console.log(`  ${c.dim}Saved to: ${USER_CRED_FILE}${c.reset}`);
    } catch (err) {
      console.log(` ${c.red}failed${c.reset}`);
      console.log(`  ${c.red}${err.message}${c.reset}`);
      return;
    }
  }

  console.log();
  console.log(`  ${c.bold}Ready!${c.reset} You can now:`);
  console.log(`  ${c.dim}•${c.reset} Discover servers: ${c.cyan}agentaudit discover${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Audit packages:   ${c.cyan}agentaudit audit <repo-url>${c.reset}  ${c.dim}(deep LLM analysis)${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Quick scan:        ${c.cyan}agentaudit scan <repo-url>${c.reset}  ${c.dim}(regex-based)${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Check registry:    ${c.cyan}agentaudit check <name>${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Submit reports via MCP in Claude/Cursor/Windsurf`);
  console.log();
}

// ── Helpers ──────────────────────────────────────────────

function getVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    return pkg.version || '0.0.0';
  } catch { return '0.0.0'; }
}

function banner() {
  if (quietMode || jsonMode) return;
  console.log();
  console.log(`  ${c.bold}${c.cyan}AgentAudit${c.reset} ${c.dim}v${getVersion()}${c.reset}`);
  console.log(`  ${c.dim}Security scanner for AI packages${c.reset}`);
  console.log();
}

function slugFromUrl(url) {
  const match = url.match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (match) return match[2].toLowerCase().replace(/[^a-z0-9-]/g, '-');
  return url.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 60);
}

function elapsed(startMs) {
  const ms = Date.now() - startMs;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function riskBadge(score) {
  if (score === 0) return `${c.bgGreen}${c.bold}${c.white} SAFE ${c.reset}`;
  if (score <= 10) return `${c.bgGreen}${c.white} LOW ${c.reset}`;
  if (score <= 30) return `${c.bgYellow}${c.bold} CAUTION ${c.reset}`;
  return `${c.bgRed}${c.bold}${c.white} UNSAFE ${c.reset}`;
}

function severityColor(sev) {
  switch (sev) {
    case 'critical': return c.red;
    case 'high': return c.red;
    case 'medium': return c.yellow;
    case 'low': return c.blue;
    default: return c.gray;
  }
}

function severityIcon(sev) {
  switch (sev) {
    case 'critical': return `${c.red}●${c.reset}`;
    case 'high': return `${c.red}●${c.reset}`;
    case 'medium': return `${c.yellow}●${c.reset}`;
    case 'low': return `${c.blue}●${c.reset}`;
    default: return `${c.green}●${c.reset}`;
  }
}

// ── File Collection (same logic as MCP server) ──────────

const MAX_FILE_SIZE = 50_000;
const MAX_TOTAL_SIZE = 300_000;
const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist', 'build',
  '.next', '.nuxt', 'coverage', '.pytest_cache', '.mypy_cache', 'vendor',
  'test', 'tests', '__tests__', 'spec', 'specs', 'docs', 'doc',
  'examples', 'example', 'fixtures', '.github', '.vscode', '.idea',
  'e2e', 'benchmark', 'benchmarks', '.tox', '.eggs', 'htmlcov',
]);
const SKIP_EXTENSIONS = new Set([
  '.lock', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
  '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.tar', '.gz',
  '.map', '.min.js', '.min.css', '.d.ts', '.pyc', '.pyo', '.so',
  '.dylib', '.dll', '.exe', '.bin', '.dat', '.db', '.sqlite',
]);

function collectFiles(dir, basePath = '', collected = [], totalSize = { bytes: 0 }) {
  if (totalSize.bytes >= MAX_TOTAL_SIZE) return collected;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return collected; }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (totalSize.bytes >= MAX_TOTAL_SIZE) break;
    const relPath = basePath ? `${basePath}/${entry.name}` : entry.name;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      collectFiles(fullPath, relPath, collected, totalSize);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) continue;
      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE || stat.size === 0) continue;
        const content = fs.readFileSync(fullPath, 'utf8');
        totalSize.bytes += content.length;
        collected.push({ path: relPath, content, size: stat.size });
      } catch {}
    }
  }
  return collected;
}

// ── Detect package properties ───────────────────────────

function detectPackageInfo(repoPath, files) {
  const info = { type: 'unknown', tools: [], prompts: [], language: 'unknown', entrypoint: null };
  
  // Detect language
  const exts = files.map(f => path.extname(f.path).toLowerCase());
  const extCounts = {};
  exts.forEach(e => { extCounts[e] = (extCounts[e] || 0) + 1; });
  const topExt = Object.entries(extCounts).sort((a, b) => b[1] - a[1])[0]?.[0];
  
  const langMap = { '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.mjs': 'JavaScript', '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.rb': 'Ruby' };
  info.language = langMap[topExt] || topExt || 'unknown';
  
  // Detect package type
  const allContent = files.map(f => f.content).join('\n');
  if (allContent.includes('@modelcontextprotocol') || allContent.includes('FastMCP') || allContent.includes('mcp.server') || allContent.includes('mcp_server')) {
    info.type = 'mcp-server';
  } else if (files.some(f => f.path.toLowerCase() === 'skill.md')) {
    info.type = 'agent-skill';
  } else if (allContent.includes('#!/usr/bin/env') || allContent.includes('argparse') || allContent.includes('commander')) {
    info.type = 'cli-tool';
  } else {
    info.type = 'library';
  }
  
  // Extract MCP tools (look for tool definitions)
  const toolPatterns = [
    // JS/TS: name: 'tool_name' or "tool_name" in tool definitions
    /(?:name|tool_name)['":\s]+['"]([a-z_][a-z0-9_]*)['"]/gi,
    // Python: @mcp.tool() def func_name or Tool(name="...")
    /(?:@(?:mcp|server)\.tool\(\)[\s\S]*?def\s+([a-z_][a-z0-9_]*))|(?:Tool\s*\(\s*name\s*=\s*['"]([a-z_][a-z0-9_]*)['"])/gi,
    // Direct: tool names in ListTools handlers
    /['"]name['"]\s*:\s*['"]([a-z_][a-z0-9_]*)['"]/gi,
  ];
  
  const toolSet = new Set();
  for (const file of files) {
    for (const pattern of toolPatterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(file.content)) !== null) {
        const name = m[1] || m[2];
        if (name && name.length > 2 && name.length < 50 && !['type', 'name', 'string', 'object', 'number', 'boolean', 'array', 'required', 'description', 'default', 'null', 'true', 'false', 'none'].includes(name)) {
          toolSet.add(name);
        }
      }
    }
  }
  info.tools = [...toolSet];
  
  // Extract prompts (look for prompt definitions)
  const promptPatterns = [
    /(?:prompt|PROMPT)['":\s]+['"]([a-z_][a-z0-9_]*)['"]/gi,
    /@(?:mcp|server)\.prompt\(\)[\s\S]*?def\s+([a-z_][a-z0-9_]*)/gi,
  ];
  const promptSet = new Set();
  for (const file of files) {
    for (const pattern of promptPatterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(file.content)) !== null) {
        if (m[1] && m[1].length > 2) promptSet.add(m[1]);
      }
    }
  }
  info.prompts = [...promptSet];
  
  // Detect entrypoint
  const entryFiles = ['index.js', 'index.ts', 'index.mjs', 'main.py', 'server.py', 'app.py', 'src/index.ts', 'src/main.ts', 'src/index.js'];
  for (const ef of entryFiles) {
    if (files.some(f => f.path === ef)) { info.entrypoint = ef; break; }
  }
  
  return info;
}

// ── Quick static checks ─────────────────────────────────

function quickChecks(files) {
  const findings = [];
  
  const checks = [
    {
      id: 'EXEC_INJECTION',
      title: 'Command injection risk',
      severity: 'high',
      pattern: /(?:exec(?:Sync)?|spawn|child_process|subprocess|os\.system|os\.popen|Popen)\s*\([^)]*(?:\$\{|`|\+\s*(?:req|input|args|param|user|query))/i,
      category: 'injection',
    },
    {
      id: 'EVAL_USAGE',
      title: 'Dynamic code evaluation',
      severity: 'high',
      pattern: /(?:^|[^a-z])eval\s*\([^)]*(?:input|req|user|param|arg|query)/im,
      category: 'injection',
    },
    {
      id: 'HARDCODED_SECRET',
      title: 'Potential hardcoded secret',
      severity: 'medium',
      pattern: /(?:api[_-]?key|password|secret|token)\s*[:=]\s*['"][A-Za-z0-9+/=_-]{16,}['"]/i,
      category: 'secrets',
    },
    {
      id: 'SSL_DISABLED',
      title: 'SSL/TLS verification disabled',
      severity: 'medium',
      pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|VERIFY_SSL\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureRequestWarning)/i,
      category: 'crypto',
    },
    {
      id: 'PATH_TRAVERSAL',
      title: 'Potential path traversal',
      severity: 'medium',
      pattern: /(?:\.\.\/|\.\.\\|path\.join|os\.path\.join)\s*\([^)]*(?:input|req|user|param|arg|query)/i,
      category: 'filesystem',
    },
    {
      id: 'CORS_WILDCARD',
      title: 'Wildcard CORS origin',
      severity: 'low',
      pattern: /(?:Access-Control-Allow-Origin|cors)\s*[:({]\s*['"]\*/i,
      category: 'network',
    },
    {
      id: 'TELEMETRY',
      title: 'Undisclosed telemetry',
      severity: 'low',
      pattern: /(?:posthog|mixpanel|analytics|telemetry|tracking|sentry).*(?:init|setup|track|capture)/i,
      category: 'privacy',
    },
    {
      id: 'SHELL_EXEC',
      title: 'Shell command execution',
      severity: 'high',
      pattern: /(?:subprocess\.(?:run|call|Popen)|os\.system|os\.popen|execSync|child_process\.exec)\s*\(/i,
      category: 'injection',
    },
    {
      id: 'SQL_INJECTION',
      title: 'Potential SQL injection',
      severity: 'high',
      pattern: /(?:execute|query|raw)\s*\(\s*(?:f['"]|['"].*?%s|['"].*?\{|['"].*?\+)/i,
      category: 'injection',
    },
    {
      id: 'YAML_UNSAFE',
      title: 'Unsafe YAML loading',
      severity: 'medium',
      pattern: /yaml\.(?:load|unsafe_load)\s*\(/i,
      category: 'deserialization',
    },
    {
      id: 'PICKLE_LOAD',
      title: 'Unsafe deserialization (pickle)',
      severity: 'high',
      pattern: /pickle\.loads?\s*\(/i,
      category: 'deserialization',
    },
    {
      id: 'PROMPT_INJECTION',
      title: 'Prompt injection vector',
      severity: 'high',
      pattern: /(?:<IMPORTANT>|<SYSTEM>|ignore previous|you are now|new instructions)/i,
      category: 'prompt-injection',
    },
  ];
  
  for (const file of files) {
    for (const check of checks) {
      const match = check.pattern.exec(file.content);
      if (match) {
        // Find line number
        const lines = file.content.slice(0, match.index).split('\n');
        findings.push({
          ...check,
          file: file.path,
          line: lines.length,
          snippet: match[0].trim().slice(0, 80),
          confidence: 'medium',
        });
      }
    }
  }
  
  return findings;
}

// ── Registry check ──────────────────────────────────────

async function checkRegistry(slug) {
  try {
    const res = await fetch(`${REGISTRY_URL}/api/packages/${encodeURIComponent(slug)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

// ── Print results ───────────────────────────────────────

function printScanResult(url, info, files, findings, registryData, duration) {
  if (jsonMode) return; // JSON mode handles output separately
  
  const slug = slugFromUrl(url);
  
  // Quiet mode: compact one-line-per-package output
  if (quietMode) {
    if (findings.length > 0) {
      const bySev = {};
      for (const f of findings) { bySev[f.severity] = (bySev[f.severity] || 0) + 1; }
      const sevStr = Object.entries(bySev).map(([s, n]) => {
        const sc = severityColor(s);
        return `${sc}${n} ${s}${c.reset}`;
      }).join(', ');
      console.log(`${icons.caution}  ${c.bold}${slug}${c.reset}  ${findings.length} findings (${sevStr})  ${c.dim}${duration}${c.reset}`);
      for (const f of findings) {
        const sc = severityColor(f.severity);
        console.log(`   ${severityIcon(f.severity)} ${sc}${f.severity.toUpperCase().padEnd(8)}${c.reset} ${f.title}  ${c.dim}${f.file}:${f.line}${c.reset}`);
      }
    } else {
      console.log(`${icons.safe}  ${c.bold}${slug}${c.reset}  ${c.green}clean${c.reset}  ${c.dim}${files.length} files, ${duration}${c.reset}`);
    }
    return;
  }
  
  // Header
  console.log(`${icons.scan}  ${c.bold}${slug}${c.reset}  ${c.dim}${url}${c.reset}`);
  console.log(`${icons.pipe}  ${c.dim}${info.language} ${info.type}${c.reset}  ${c.dim}${files.length} files scanned in ${duration}${c.reset}`);
  
  // Tools & prompts tree
  const items = [
    ...info.tools.map(t => ({ kind: 'tool', name: t })),
    ...info.prompts.map(p => ({ kind: 'prompt', name: p })),
  ];
  
  if (items.length > 0) {
    console.log(`${icons.pipe}`);
    for (let i = 0; i < items.length; i++) {
      const isLast = i === items.length - 1 && findings.length === 0;
      const branch = isLast ? icons.treeLast : icons.tree;
      const item = items[i];
      const kindLabel = item.kind === 'tool' ? `${c.dim}tool${c.reset}  ` : `${c.dim}prompt${c.reset}`;
      const padName = item.name.padEnd(28);
      
      // Check if this tool has a finding associated
      const toolFinding = findings.find(f => 
        f.snippet && f.snippet.toLowerCase().includes(item.name.toLowerCase())
      );
      
      if (toolFinding) {
        const sc = severityColor(toolFinding.severity);
        console.log(`${branch}  ${kindLabel}  ${c.bold}${padName}${c.reset} ${sc}⚠ flagged${c.reset} — ${toolFinding.title}`);
      } else {
        console.log(`${branch}  ${kindLabel}  ${c.bold}${padName}${c.reset} ${c.green}✔ ok${c.reset}`);
      }
    }
  } else {
    console.log(`${icons.pipe}  ${c.dim}(no tools or prompts detected)${c.reset}`);
  }
  
  // Findings
  if (findings.length > 0) {
    console.log(`${icons.pipe}`);
    console.log(`${icons.pipe}  ${c.bold}Findings (${findings.length})${c.reset}  ${c.dim}static analysis — may include false positives${c.reset}`);
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const isLast = i === findings.length - 1;
      const branch = isLast ? icons.treeLast : icons.tree;
      const pipeOrSpace = isLast ? '   ' : `${icons.pipe}  `;
      const sc = severityColor(f.severity);
      console.log(`${branch}  ${severityIcon(f.severity)} ${sc}${f.severity.toUpperCase().padEnd(8)}${c.reset} ${f.title}`);
      console.log(`${pipeOrSpace}   ${c.dim}${f.file}:${f.line}${c.reset}  ${c.dim}${f.snippet || ''}${c.reset}`);
    }
  }
  
  // Registry status
  console.log(`${icons.pipe}`);
  if (registryData) {
    const rd = registryData;
    const riskScore = rd.risk_score ?? rd.latest_risk_score ?? 0;
    console.log(`${icons.treeLast}  ${c.dim}registry${c.reset}  ${riskBadge(riskScore)} Risk ${riskScore}  ${c.dim}${REGISTRY_URL}/packages/${slug}${c.reset}`);
  } else {
    console.log(`${icons.treeLast}  ${c.dim}registry${c.reset}  ${c.dim}not audited yet${c.reset}`);
  }
  
  console.log();
}

function printSummary(results) {
  const total = results.length;
  const safe = results.filter(r => r.findings.length === 0).length;
  const withFindings = total - safe;
  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  
  console.log(`${c.dim}${'─'.repeat(60)}${c.reset}`);
  console.log(`  ${c.bold}Summary${c.reset}  ${total} packages scanned`);
  console.log();
  if (safe > 0) console.log(`  ${icons.safe}  ${c.green}${safe} clean${c.reset}`);
  if (withFindings > 0) console.log(`  ${icons.caution}  ${c.yellow}${withFindings} with findings${c.reset} (${totalFindings} total)`);
  
  // Breakdown by severity
  const bySev = {};
  results.forEach(r => r.findings.forEach(f => {
    bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  }));
  if (Object.keys(bySev).length > 0) {
    console.log();
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      if (bySev[sev]) {
        console.log(`    ${severityIcon(sev)} ${bySev[sev]}× ${severityColor(sev)}${sev}${c.reset}`);
      }
    }
  }
  
  console.log();
}

// ── Clone & Scan ────────────────────────────────────────

async function scanRepo(url) {
  const start = Date.now();
  const slug = slugFromUrl(url);
  
  if (!jsonMode) process.stdout.write(`${icons.scan}  Scanning ${c.bold}${slug}${c.reset} ${c.dim}...${c.reset}`);
  
  // Clone
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-'));
  const repoPath = path.join(tmpDir, 'repo');
  try {
    execSync(`git clone --depth 1 "${url}" "${repoPath}"`, {
      timeout: 30_000,
      stdio: 'pipe',
    });
  } catch (err) {
    if (!jsonMode) {
      process.stdout.write(`  ${c.red}✖ clone failed${c.reset}\n`);
      const msg = err.stderr?.toString().trim() || err.message?.split('\n')[0] || '';
      if (msg) console.log(`    ${c.dim}${msg}${c.reset}`);
      console.log(`    ${c.dim}Make sure git is installed and the URL is accessible.${c.reset}`);
    }
    return null;
  }
  
  // Collect files
  const files = collectFiles(repoPath);
  
  // Detect info
  const info = detectPackageInfo(repoPath, files);
  
  // Quick checks
  const findings = quickChecks(files);
  
  // Registry lookup
  const registryData = await checkRegistry(slug);
  
  // Cleanup
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  
  const duration = elapsed(start);
  
  if (!jsonMode) {
    // Clear the "Scanning..." line
    process.stdout.write('\r\x1b[K');
    
    // Print result
    printScanResult(url, info, files, findings, registryData, duration);
  }
  
  return { slug, url, info, files: files.length, findings, registryData, duration };
}

// ── Discover local MCP configs ──────────────────────────

function findMcpConfigs() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const platform = process.platform;
  
  // All known MCP config locations
  const candidates = [
    // Claude Desktop
    { name: 'Claude Desktop', path: path.join(home, '.claude', 'mcp.json') },
    { name: 'Claude Desktop', path: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') },
    { name: 'Claude Desktop', path: path.join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json') },
    { name: 'Claude Desktop', path: path.join(home, '.config', 'claude', 'claude_desktop_config.json') },
    // Cursor
    { name: 'Cursor', path: path.join(home, '.cursor', 'mcp.json') },
    // Windsurf / Codeium
    { name: 'Windsurf', path: path.join(home, '.codeium', 'windsurf', 'mcp_config.json') },
    // VS Code
    { name: 'VS Code', path: path.join(home, '.vscode', 'mcp.json') },
    // Continue.dev
    { name: 'Continue', path: path.join(home, '.continue', 'config.json') },
  ];
  
  // Also check AGENTAUDIT_TEST_CONFIG env for testing
  if (process.env.AGENTAUDIT_TEST_CONFIG) {
    candidates.push({ name: 'Test Config', path: process.env.AGENTAUDIT_TEST_CONFIG });
  }
  
  // Also scan workspace .cursor/mcp.json, .vscode/mcp.json in cwd
  const cwd = process.cwd();
  candidates.push(
    { name: 'Cursor (project)', path: path.join(cwd, '.cursor', 'mcp.json') },
    { name: 'VS Code (project)', path: path.join(cwd, '.vscode', 'mcp.json') },
  );
  
  const found = [];
  for (const c of candidates) {
    if (fs.existsSync(c.path)) {
      try {
        const content = JSON.parse(fs.readFileSync(c.path, 'utf8'));
        found.push({ ...c, content });
      } catch {}
    }
  }
  return found;
}

function extractServersFromConfig(config) {
  // Handle both { mcpServers: {...} } and { servers: {...} } formats
  const servers = config.mcpServers || config.servers || {};
  const result = [];
  
  for (const [name, serverConfig] of Object.entries(servers)) {
    const info = {
      name,
      command: serverConfig.command || null,
      args: serverConfig.args || [],
      url: serverConfig.url || null,
      sourceUrl: null,
    };
    
    // Try to extract source URL from args (common patterns)
    const allArgs = [info.command, ...info.args].filter(Boolean).join(' ');
    
    // npx package-name → npm package
    const npxMatch = allArgs.match(/npx\s+(?:-y\s+)?(@?[a-z0-9][\w./-]*)/i);
    if (npxMatch) info.npmPackage = npxMatch[1];
    
    // node /path/to/something → try to find package.json
    const nodePathMatch = allArgs.match(/node\s+["']?([^"'\s]+)/);
    if (nodePathMatch) {
      const scriptPath = nodePathMatch[1];
      // Walk up to find package.json with repository
      let dir = path.dirname(path.resolve(scriptPath));
      for (let i = 0; i < 5; i++) {
        const pkgPath = path.join(dir, 'package.json');
        if (fs.existsSync(pkgPath)) {
          try {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
            if (pkg.repository?.url) {
              info.sourceUrl = pkg.repository.url.replace(/^git\+/, '').replace(/\.git$/, '');
            }
            if (pkg.name) info.npmPackage = pkg.name;
          } catch {}
          break;
        }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
      }
    }
    
    // python/uvx with package name
    const pyMatch = allArgs.match(/(?:uvx|pip run|python -m)\s+(@?[a-z0-9][\w./-]*)/i);
    if (pyMatch) info.pyPackage = pyMatch[1];
    
    // URL-based MCP server (remote HTTP)
    if (info.url && !info.npmPackage && !info.pyPackage) {
      try {
        const parsed = new URL(info.url);
        // Extract service name from hostname: mcp.supabase.com → supabase
        const hostParts = parsed.hostname.split('.');
        if (hostParts.length >= 2) {
          const serviceName = hostParts.length === 3 ? hostParts[1] : hostParts[0];
          info.remoteService = serviceName;
        }
      } catch {}
    }
    
    result.push(info);
  }
  return result;
}

function serverSlug(server) {
  // Try to derive a slug for registry lookup
  if (server.npmPackage) return server.npmPackage.replace(/^@/, '').replace(/\//g, '-');
  if (server.pyPackage) return server.pyPackage.replace(/[^a-z0-9-]/gi, '-');
  return server.name.toLowerCase().replace(/[^a-z0-9-]/gi, '-');
}

async function searchGitHub(query) {
  try {
    const res = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&per_page=1`, {
      signal: AbortSignal.timeout(5000),
      headers: { 'Accept': 'application/vnd.github+json' },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.items?.length > 0) {
        return data.items[0].html_url;
      }
    }
  } catch {}
  return null;
}

async function resolveSourceUrl(server) {
  // Already have it
  if (server.sourceUrl) return server.sourceUrl;
  
  // Try npm registry
  if (server.npmPackage) {
    try {
      const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(server.npmPackage)}`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = await res.json();
        let repoUrl = data.repository?.url;
        if (repoUrl) {
          repoUrl = repoUrl.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^ssh:\/\/git@github\.com/, 'https://github.com');
          if (repoUrl.startsWith('http')) return repoUrl;
        }
      }
    } catch {}
    // Fallback: try GitHub search for the package name
    const ghUrl = await searchGitHub(server.npmPackage);
    if (ghUrl) return ghUrl;
    return `https://www.npmjs.com/package/${server.npmPackage}`;
  }
  
  // Try PyPI
  if (server.pyPackage) {
    try {
      const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(server.pyPackage)}/json`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = await res.json();
        const urls = data.info?.project_urls || {};
        const source = urls.Source || urls.Repository || urls.Homepage || urls['Source Code'] || data.info?.home_page;
        if (source && source.startsWith('http')) return source;
      }
    } catch {}
    // Fallback: GitHub search
    const ghUrl = await searchGitHub(server.pyPackage);
    if (ghUrl) return ghUrl;
    return `https://pypi.org/project/${server.pyPackage}/`;
  }
  
  // URL-based remote MCP server — try GitHub search by service name
  if (server.remoteService) {
    // Try npm registry with common MCP naming patterns
    for (const tryName of [
      `@${server.remoteService}/mcp-server-${server.remoteService}`,
      `${server.remoteService}-mcp`,
      `mcp-server-${server.remoteService}`,
      server.remoteService,
    ]) {
      try {
        const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(tryName)}`, {
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const data = await res.json();
          let repoUrl = data.repository?.url;
          if (repoUrl) {
            repoUrl = repoUrl.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^ssh:\/\/git@github\.com/, 'https://github.com');
            if (repoUrl.startsWith('http')) return repoUrl;
          }
        }
      } catch {}
    }
  }
  
  // Last resort: if server has a url, show it as context
  if (server.url) {
    try {
      const parsed = new URL(server.url);
      return `https://github.com/search?q=${encodeURIComponent(parsed.hostname + ' MCP')}&type=repositories`;
    } catch {}
  }
  
  return null;
}

async function discoverCommand(options = {}) {
  const autoScan = options.scan || false;
  const interactiveAudit = options.audit || false;
  
  if (!jsonMode) {
    console.log(`  ${c.bold}Discovering MCP servers in your AI editors...${c.reset}`);
    console.log();
  }
  
  const configs = findMcpConfigs();
  
  if (configs.length === 0) {
    console.log(`  ${c.yellow}No MCP configurations found.${c.reset}`);
    console.log(`  ${c.dim}Searched: Claude Desktop, Cursor, Windsurf, VS Code${c.reset}`);
    console.log();
    console.log(`  ${c.dim}MCP config locations:${c.reset}`);
    console.log(`  ${c.dim}  Claude:   ~/.claude/mcp.json${c.reset}`);
    console.log(`  ${c.dim}  Cursor:   ~/.cursor/mcp.json${c.reset}`);
    console.log(`  ${c.dim}  Windsurf: ~/.codeium/windsurf/mcp_config.json${c.reset}`);
    console.log(`  ${c.dim}  VS Code:  ~/.vscode/mcp.json${c.reset}`);
    console.log();
    return;
  }
  
  let totalServers = 0;
  let checkedServers = 0;
  let auditedServers = 0;
  let unauditedServers = 0;
  const unauditedWithUrls = [];
  const allServersWithUrls = []; // For --scan: all servers we can scan
  
  for (const config of configs) {
    const servers = extractServersFromConfig(config.content);
    const serverCount = servers.length;
    totalServers += serverCount;
    
    const countLabel = serverCount === 0
      ? `${c.dim}no servers${c.reset}`
      : `found ${c.bold}${serverCount}${c.reset} server${serverCount > 1 ? 's' : ''}`;
    
    console.log(`${icons.bullet}  Scanning ${c.bold}${config.name}${c.reset}  ${c.dim}${config.path}${c.reset}    ${countLabel}`);
    
    if (serverCount === 0) {
      console.log();
      continue;
    }
    
    console.log();
    
    for (let i = 0; i < servers.length; i++) {
      const server = servers[i];
      const isLast = i === servers.length - 1;
      const branch = isLast ? icons.treeLast : icons.tree;
      const pipe = isLast ? '   ' : `${icons.pipe}  `;
      
      const slug = serverSlug(server);
      checkedServers++;
      
      // Registry lookup
      const registryData = await checkRegistry(slug);
      
      // Also try with server name directly
      let regData = registryData;
      if (!regData && slug !== server.name.toLowerCase()) {
        regData = await checkRegistry(server.name.toLowerCase());
      }
      
      // Determine source display
      let sourceLabel = '';
      if (server.npmPackage) sourceLabel = `${c.dim}npm:${server.npmPackage}${c.reset}`;
      else if (server.pyPackage) sourceLabel = `${c.dim}pip:${server.pyPackage}${c.reset}`;
      else if (server.url) sourceLabel = `${c.dim}${server.url.length > 60 ? server.url.slice(0, 57) + '...' : server.url}${c.reset}`;
      else if (server.command) sourceLabel = `${c.dim}${[server.command, ...server.args.slice(0, 2)].join(' ')}${c.reset}`;
      
      // Always resolve source URL (needed for --scan)
      const resolvedUrl = await resolveSourceUrl(server);
      
      if (regData) {
        auditedServers++;
        const riskScore = regData.risk_score ?? regData.latest_risk_score ?? 0;
        const hasOfficial = regData.has_official_audit;
        console.log(`${branch}  ${c.bold}${server.name}${c.reset}    ${sourceLabel}`);
        console.log(`${pipe}  ${riskBadge(riskScore)} Risk ${riskScore}  ${hasOfficial ? `${c.green}✔ official${c.reset}  ` : ''}${c.dim}${REGISTRY_URL}/packages/${slug}${c.reset}`);
        if (resolvedUrl) allServersWithUrls.push({ name: server.name, sourceUrl: resolvedUrl, hasAudit: true, regData });
      } else {
        unauditedServers++;
        console.log(`${branch}  ${c.bold}${server.name}${c.reset}    ${sourceLabel}`);
        if (resolvedUrl) {
          console.log(`${pipe}  ${c.yellow}⚠ not audited${c.reset}  ${c.dim}Run: ${c.cyan}agentaudit audit ${resolvedUrl} --verify self${c.reset}`);
          unauditedWithUrls.push({ name: server.name, sourceUrl: resolvedUrl });
          allServersWithUrls.push({ name: server.name, sourceUrl: resolvedUrl, hasAudit: false });
        } else {
          console.log(`${pipe}  ${c.yellow}⚠ not audited${c.reset}  ${c.dim}Source URL unknown — check the package's GitHub/npm page${c.reset}`);
        }
      }
      
      if (server.sourceUrl && !server.sourceUrl.includes('npmjs.com')) {
        console.log(`${pipe}  ${c.dim}source: ${server.sourceUrl}${c.reset}`);
      }
    }
    
    console.log();
  }
  
  // Summary
  console.log(`${c.dim}${'─'.repeat(60)}${c.reset}`);
  console.log(`  ${c.bold}Summary${c.reset}  ${totalServers} server${totalServers !== 1 ? 's' : ''} across ${configs.length} config${configs.length !== 1 ? 's' : ''}`);
  console.log();
  if (auditedServers > 0) console.log(`  ${icons.safe}  ${c.green}${auditedServers} audited${c.reset}`);
  if (unauditedServers > 0) console.log(`  ${icons.caution}  ${c.yellow}${unauditedServers} not audited${c.reset}`);
  console.log();
  
  // --scan: automatically scan all servers with resolved source URLs (git-cloneable only)
  if (autoScan) {
    const isCloneable = (url) => /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\//i.test(url);
    const scanTargets = allServersWithUrls.filter(s => s.sourceUrl && isCloneable(s.sourceUrl));
    // Deduplicate by sourceUrl
    const seen = new Set();
    const dedupedTargets = scanTargets.filter(s => {
      if (seen.has(s.sourceUrl)) return false;
      seen.add(s.sourceUrl);
      return true;
    });
    const skipped = allServersWithUrls.filter(s => s.sourceUrl && !isCloneable(s.sourceUrl));
    if (dedupedTargets.length > 0) {
      console.log(`${c.dim}${'─'.repeat(60)}${c.reset}`);
      console.log(`  ${c.bold}${icons.scan}  Auto-scanning ${dedupedTargets.length} server${dedupedTargets.length !== 1 ? 's' : ''}...${c.reset}`);
      if (skipped.length > 0) {
        console.log(`  ${c.dim}(${skipped.length} skipped — no cloneable source URL)${c.reset}`);
      }
      console.log();
      
      const scanResults = [];
      for (const target of dedupedTargets) {
        const result = await scanRepo(target.sourceUrl);
        if (result) scanResults.push({ ...result, serverName: target.name });
      }
      
      if (scanResults.length > 1) {
        // Print combined scan summary
        console.log(`${c.dim}${'─'.repeat(60)}${c.reset}`);
        console.log(`  ${c.bold}Scan Summary${c.reset}  ${scanResults.length} server${scanResults.length !== 1 ? 's' : ''} scanned`);
        console.log();
        
        let totalFindings = 0;
        let serversWithFindings = 0;
        
        for (const r of scanResults) {
          const findingCount = r.findings ? r.findings.length : 0;
          totalFindings += findingCount;
          if (findingCount > 0) serversWithFindings++;
          
          const status = findingCount === 0
            ? `${icons.safe}  ${c.green}clean${c.reset}`
            : `${icons.caution}  ${c.yellow}${findingCount} finding${findingCount !== 1 ? 's' : ''}${c.reset}`;
          console.log(`  ${status}  ${c.bold}${r.serverName || r.slug}${c.reset}  ${c.dim}(${r.duration})${c.reset}`);
        }
        
        console.log();
        if (serversWithFindings > 0) {
          console.log(`  ${c.yellow}${serversWithFindings}/${scanResults.length} server${scanResults.length !== 1 ? 's' : ''} with findings (${totalFindings} total)${c.reset}`);
          console.log(`  ${c.dim}Run ${c.cyan}agentaudit scan <url> --deep${c.dim} for deep LLM analysis on flagged servers${c.reset}`);
        } else {
          console.log(`  ${c.green}All servers passed quick scan${c.reset}`);
          console.log(`  ${c.dim}Run ${c.cyan}agentaudit scan <url> --deep${c.dim} for thorough LLM-powered analysis${c.reset}`);
        }
        console.log();
      }
    } else {
      console.log(`  ${c.dim}No scannable source URLs found.${c.reset}`);
      console.log();
    }
  } else if (interactiveAudit && allServersWithUrls.length > 0) {
    // Interactive multi-select for audit
    const isCloneable = (url) => /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\//i.test(url);
    const auditCandidates = [];
    const seen = new Set();
    for (const s of allServersWithUrls) {
      if (!s.sourceUrl || !isCloneable(s.sourceUrl)) continue;
      if (seen.has(s.sourceUrl)) continue;
      seen.add(s.sourceUrl);
      auditCandidates.push(s);
    }
    
    if (auditCandidates.length > 0) {
      console.log();
      const items = auditCandidates.map(s => ({
        label: s.name,
        sublabel: s.hasAudit ? `${c.green}✔ audited${c.reset}  ${s.sourceUrl}` : s.sourceUrl,
        value: s,
        checked: !s.hasAudit, // Pre-select unaudited
      }));
      
      const selected = await multiSelect(items, {
        title: 'Select servers to audit',
        hint: 'Space=toggle  ↑↓=move  a=all  n=none  Enter=confirm',
      });
      
      if (selected.length > 0) {
        console.log();
        console.log(`  ${c.bold}Auditing ${selected.length} server${selected.length !== 1 ? 's' : ''}...${c.reset}`);
        console.log();
        for (const s of selected) {
          await auditRepo(s.sourceUrl);
          console.log();
        }
      } else {
        console.log();
        console.log(`  ${c.dim}No servers selected.${c.reset}`);
      }
    }
  } else if (unauditedServers > 0) {
    if (unauditedWithUrls.length > 0) {
      console.log(`  ${c.dim}To audit unaudited servers:${c.reset}`);
      for (const { name, sourceUrl } of unauditedWithUrls) {
        console.log(`  ${c.cyan}agentaudit audit ${sourceUrl} --verify self${c.reset}  ${c.dim}(${name})${c.reset}`);
      }
    } else {
      console.log(`  ${c.dim}To audit unaudited servers, run:${c.reset}`);
      console.log(`  ${c.cyan}agentaudit audit <source-url> --verify self${c.reset}`);
    }
    console.log();
    console.log(`  ${c.dim}Or run ${c.cyan}agentaudit discover --quick${c.dim} to quick-scan all servers${c.reset}`);
    console.log(`  ${c.dim}Or run ${c.cyan}agentaudit discover --deep${c.dim} to select & deep-audit interactively${c.reset}`);
    console.log();
  }
  
  if (!autoScan && !interactiveAudit && !jsonMode) {
    console.log(`  ${c.dim}Looking for general package scanning? Try ${c.cyan}pip audit${c.dim} or ${c.cyan}npm audit${c.dim}.${c.reset}`);
    console.log();
  }
}

// ── Audit command (deep LLM-powered) ────────────────────

function loadAuditPrompt() {
  const promptPath = path.join(SKILL_DIR, 'prompts', 'audit-prompt.md');
  if (fs.existsSync(promptPath)) return fs.readFileSync(promptPath, 'utf8');
  return null;
}

async function auditRepo(url) {
  const start = Date.now();
  const slug = slugFromUrl(url);
  
  console.log(`${icons.scan}  ${c.bold}Auditing ${slug}${c.reset}  ${c.dim}${url}${c.reset}`);
  console.log(`${icons.pipe}  ${c.dim}Deep LLM-powered analysis (3-pass: UNDERSTAND → DETECT → CLASSIFY)${c.reset}`);
  console.log();
  
  // Step 1: Clone
  process.stdout.write(`  ${c.dim}[1/4]${c.reset} Cloning repository...`);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-'));
  const repoPath = path.join(tmpDir, 'repo');
  try {
    execSync(`git clone --depth 1 "${url}" "${repoPath}"`, {
      timeout: 30_000, stdio: 'pipe',
    });
    console.log(` ${c.green}done${c.reset}`);
  } catch (err) {
    console.log(` ${c.red}failed${c.reset}`);
    const msg = err.stderr?.toString().trim() || err.message?.split('\n')[0] || '';
    if (msg) console.log(`    ${c.dim}${msg}${c.reset}`);
    console.log(`    ${c.dim}Make sure git is installed and the URL is accessible.${c.reset}`);
    return null;
  }
  
  // Step 2: Collect files
  process.stdout.write(`  ${c.dim}[2/4]${c.reset} Collecting source files...`);
  const files = collectFiles(repoPath);
  console.log(` ${c.green}${files.length} files${c.reset}`);
  
  // Step 3: Build audit payload
  process.stdout.write(`  ${c.dim}[3/4]${c.reset} Preparing audit payload...`);
  const auditPrompt = loadAuditPrompt();
  
  let codeBlock = '';
  for (const file of files) {
    codeBlock += `\n### FILE: ${file.path}\n\`\`\`\n${file.content}\n\`\`\`\n`;
  }
  console.log(` ${c.green}done${c.reset}`);
  
  // Step 4: LLM Analysis
  // Check for API keys to determine which LLM to use
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;
  
  if (!anthropicKey && !openaiKey) {
    // No LLM API key — clear explanation
    console.log();
    console.log(`  ${c.yellow}No LLM API key found.${c.reset} The ${c.bold}audit${c.reset} command needs an LLM to analyze code.`);
    console.log();
    console.log(`  ${c.bold}Option 1: Set an API key${c.reset}`);
    console.log(`  Supported keys: ${c.cyan}ANTHROPIC_API_KEY${c.reset} or ${c.cyan}OPENAI_API_KEY${c.reset}`);
    console.log();
    console.log(`  ${c.dim}# Linux / macOS:${c.reset}`);
    console.log(`  ${c.dim}export ANTHROPIC_API_KEY=sk-ant-...${c.reset}`);
    console.log(`  ${c.dim}export OPENAI_API_KEY=sk-...${c.reset}`);
    console.log();
    console.log(`  ${c.dim}# Windows (PowerShell):${c.reset}`);
    console.log(`  ${c.dim}$env:ANTHROPIC_API_KEY = "sk-ant-..."${c.reset}`);
    console.log(`  ${c.dim}$env:OPENAI_API_KEY = "sk-..."${c.reset}`);
    console.log();
    console.log(`  ${c.dim}# Windows (CMD):${c.reset}`);
    console.log(`  ${c.dim}set ANTHROPIC_API_KEY=sk-ant-...${c.reset}`);
    console.log(`  ${c.dim}set OPENAI_API_KEY=sk-...${c.reset}`);
    console.log();
    console.log(`  ${c.bold}Option 2: Export for manual review${c.reset}`);
    console.log(`  ${c.cyan}agentaudit audit ${url} --verify self --export${c.reset}`);
    console.log(`  ${c.dim}Creates a markdown file you can paste into any LLM (Claude, ChatGPT, etc.)${c.reset}`);
    console.log();
    console.log(`  ${c.bold}Option 3: Use MCP in Claude/Cursor/Windsurf (no API key needed)${c.reset}`);
    console.log(`  ${c.dim}Add AgentAudit as MCP server — your editor's agent runs the audit using its own LLM.${c.reset}`);
    console.log(`  ${c.dim}Config: { "mcpServers": { "agentaudit": { "command": "npx", "args": ["-y", "agentaudit"] } } }${c.reset}`);
    console.log();
    
    // Check if --export flag
    if (process.argv.includes('--export')) {
      const exportPath = path.join(process.cwd(), `audit-${slug}.md`);
      const exportContent = [
        `# Security Audit: ${slug}`,
        `**Source:** ${url}`,
        `**Files:** ${files.length}`,
        ``,
        `## Audit Instructions`,
        ``,
        auditPrompt || '(audit prompt not found)',
        ``,
        `## Report Format`,
        ``,
        `After analysis, produce a JSON report:`,
        '```json',
        `{ "skill_slug": "${slug}", "source_url": "${url}", "risk_score": 0, "result": "safe", "findings": [] }`,
        '```',
        ``,
        `## Source Code`,
        ``,
        codeBlock,
      ].join('\n');
      fs.writeFileSync(exportPath, exportContent);
      console.log(`  ${icons.safe}  Exported to ${c.bold}${exportPath}${c.reset}`);
      console.log(`  ${c.dim}Paste this into any LLM (Claude, ChatGPT, etc.) for analysis${c.reset}`);
    }
    
    // Cleanup
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    return null;
  }
  
  // We have an API key — run LLM audit
  process.stdout.write(`  ${c.dim}[4/4]${c.reset} Running LLM analysis...`);
  
  const systemPrompt = auditPrompt || 'You are a security auditor. Analyze the code and report findings as JSON.';
  const userMessage = [
    `Audit this package: **${slug}** (${url})`,
    ``,
    `After analysis, respond with ONLY a JSON object (no markdown, no explanation):`,
    '```',
    `{ "skill_slug": "${slug}", "source_url": "${url}", "package_type": "<mcp-server|agent-skill|library|cli-tool>",`,
    `  "risk_score": <0-100>, "result": "<safe|caution|unsafe>", "max_severity": "<none|low|medium|high|critical>",`,
    `  "findings_count": <n>, "findings": [{ "id": "...", "title": "...", "severity": "...", "category": "...",`,
    `  "description": "...", "file": "...", "line": <n>, "remediation": "...", "confidence": "...", "is_by_design": false }] }`,
    '```',
    ``,
    `## Source Code`,
    codeBlock,
  ].join('\n');
  
  let report = null;
  
  try {
    if (anthropicKey) {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': anthropicKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 8192,
          system: systemPrompt,
          messages: [{ role: 'user', content: userMessage }],
        }),
        signal: AbortSignal.timeout(120_000),
      });
      const data = await res.json();
      const text = data.content?.[0]?.text || '';
      // Extract JSON from response
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) report = JSON.parse(jsonMatch[0]);
    } else if (openaiKey) {
      const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${openaiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'gpt-4o',
          max_tokens: 8192,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userMessage },
          ],
        }),
        signal: AbortSignal.timeout(120_000),
      });
      const data = await res.json();
      const text = data.choices?.[0]?.message?.content || '';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) report = JSON.parse(jsonMatch[0]);
    }
    
    console.log(` ${c.green}done${c.reset} ${c.dim}(${elapsed(start)})${c.reset}`);
  } catch (err) {
    console.log(` ${c.red}failed${c.reset}`);
    console.log(`  ${c.red}${err.message}${c.reset}`);
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    return null;
  }
  
  // Cleanup repo
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  
  if (!report) {
    console.log(`  ${c.red}Could not parse LLM response as JSON${c.reset}`);
    return null;
  }
  
  // Display results
  console.log();
  const riskScore = report.risk_score || 0;
  console.log(`  ${riskBadge(riskScore)} Risk ${riskScore}/100  ${c.bold}${report.result || 'unknown'}${c.reset}`);
  console.log();
  
  if (report.findings && report.findings.length > 0) {
    console.log(`  ${c.bold}Findings (${report.findings.length})${c.reset}`);
    console.log();
    for (const f of report.findings) {
      const sc = severityColor(f.severity);
      console.log(`  ${severityIcon(f.severity)} ${sc}${(f.severity || '').toUpperCase().padEnd(8)}${c.reset} ${f.title}`);
      if (f.file) console.log(`    ${c.dim}${f.file}${f.line ? ':' + f.line : ''}${c.reset}`);
      if (f.description) console.log(`    ${c.dim}${f.description.slice(0, 120)}${c.reset}`);
      console.log();
    }
  } else {
    console.log(`  ${c.green}No findings — package looks clean.${c.reset}`);
    console.log();
  }
  
  // Upload to registry
  const creds = loadCredentials();
  if (creds) {
    process.stdout.write(`  Uploading report to registry...`);
    try {
      const res = await fetch(`${REGISTRY_URL}/api/reports`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${creds.api_key}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(report),
        signal: AbortSignal.timeout(15_000),
      });
      if (res.ok) {
        const data = await res.json();
        console.log(` ${c.green}done${c.reset}`);
        console.log(`  ${c.dim}Report: ${REGISTRY_URL}/packages/${slug}${c.reset}`);
      } else {
        console.log(` ${c.yellow}failed (HTTP ${res.status})${c.reset}`);
      }
    } catch (err) {
      console.log(` ${c.yellow}failed${c.reset}`);
    }
  } else {
    console.log(`  ${c.dim}Run ${c.cyan}agentaudit setup${c.dim} to upload reports to the registry${c.reset}`);
  }
  
  console.log();
  return report;
}

// ── Check command ───────────────────────────────────────

async function checkPackage(name) {
  if (!jsonMode) {
    console.log(`${icons.info}  Looking up ${c.bold}${name}${c.reset} in registry...`);
    console.log();
  }
  
  const data = await checkRegistry(name);
  if (!data) {
    if (!jsonMode) {
      console.log(`  ${c.yellow}Not found${c.reset} — package "${name}" hasn't been audited yet.`);
      console.log(`  ${c.dim}Run: agentaudit audit <repo-url> --verify self for a deep LLM audit${c.reset}`);
    }
    return null;
  }
  
  if (!jsonMode) {
    const riskScore = data.risk_score ?? data.latest_risk_score ?? 0;
    console.log(`  ${c.bold}${name}${c.reset}  ${riskBadge(riskScore)}`);
    console.log(`  ${c.dim}Risk Score: ${riskScore}/100${c.reset}`);
    if (data.source_url) console.log(`  ${c.dim}Source: ${data.source_url}${c.reset}`);
    console.log(`  ${c.dim}Registry: ${REGISTRY_URL}/packages/${name}${c.reset}`);
    if (data.has_official_audit) console.log(`  ${c.green}✔ Officially audited${c.reset}`);
    console.log();
  }
  return data;
}

// ── Main ────────────────────────────────────────────────

async function main() {
  const rawArgs = process.argv.slice(2);
  
  // Parse global flags early
  jsonMode = rawArgs.includes('--json');
  quietMode = rawArgs.includes('--quiet') || rawArgs.includes('-q');
  // --no-color already handled at top level for `c` object
  
  // Strip global flags from args
  const globalFlags = new Set(['--json', '--quiet', '-q', '--no-color']);
  const args = rawArgs.filter(a => !globalFlags.has(a));
  
  if (args[0] === '-v' || args[0] === '--version') {
    console.log(`agentaudit ${getVersion()}`);
    process.exitCode = 0; return;
  }
  
  if (args[0] === '--help' || args[0] === '-h') {
    banner();
    console.log(`  ${c.bold}Commands:${c.reset}`);
    console.log();
    console.log(`    ${c.cyan}agentaudit${c.reset}                                   Discover MCP servers (same as discover)`);
    console.log(`    ${c.cyan}agentaudit discover${c.reset}                          Find MCP servers in your AI editors (Cursor, Claude, VS Code, Windsurf)`);
    console.log(`    ${c.cyan}agentaudit discover --quick${c.reset}                  Discover + auto-scan all servers`);
    console.log(`    ${c.cyan}agentaudit discover --deep${c.reset}                   Discover + select servers to deep-audit`);
    console.log(`    ${c.cyan}agentaudit scan${c.reset} <url> [url...]               Quick static scan (regex, local)`);
    console.log(`    ${c.cyan}agentaudit scan${c.reset} <url> ${c.dim}--deep${c.reset}                Deep audit (same as audit)`);
    console.log(`    ${c.cyan}agentaudit audit${c.reset} <url> [url...]              Deep LLM-powered security audit`);
    console.log(`    ${c.cyan}agentaudit audit${c.reset} <url> ${c.dim}--verify self${c.reset}        Audit + verification pass (default)`);
    console.log(`    ${c.cyan}agentaudit lookup${c.reset} <name>                     Look up package in registry`);
    console.log(`    ${c.cyan}agentaudit setup${c.reset}                             Register + configure API key`);
    console.log();
    console.log(`  ${c.bold}Global flags:${c.reset}`);
    console.log(`    ${c.dim}--json       Output JSON to stdout (machine-readable)${c.reset}`);
    console.log(`    ${c.dim}--quiet      Suppress banner and tree visualization${c.reset}`);
    console.log(`    ${c.dim}--no-color   Disable ANSI colors (also: NO_COLOR env)${c.reset}`);
    console.log();
    console.log(`  ${c.bold}Quick Scan${c.reset} vs ${c.bold}Deep Audit${c.reset}:`);
    console.log(`    ${c.dim}scan  = fast regex-based static analysis (~2s)${c.reset}`);
    console.log(`    ${c.dim}audit = deep LLM analysis with 3-pass methodology + verification (~30-60s)${c.reset}`);
    console.log();
    console.log(`  ${c.bold}Exit codes:${c.reset}`);
    console.log(`    ${c.dim}0 = clean / success    1 = findings detected    2 = error${c.reset}`);
    console.log();
    console.log(`  ${c.bold}Examples:${c.reset}`);
    console.log(`    agentaudit`);
    console.log(`    agentaudit discover --quick`);
    console.log(`    agentaudit scan https://github.com/owner/repo`);
    console.log(`    agentaudit audit https://github.com/owner/repo --verify self`);
    console.log(`    agentaudit lookup fastmcp --json`);
    console.log();
    console.log(`  ${c.bold}For deep audits,${c.reset} set an LLM API key:`);
    if (process.platform === 'win32') {
      console.log(`    ${c.dim}PowerShell:  $env:ANTHROPIC_API_KEY = "sk-ant-..."${c.reset}`);
      console.log(`    ${c.dim}CMD:         set ANTHROPIC_API_KEY=sk-ant-...${c.reset}`);
      console.log(`    ${c.dim}(or use OPENAI_API_KEY instead)${c.reset}`);
    } else {
      console.log(`    ${c.dim}export ANTHROPIC_API_KEY=sk-ant-...${c.reset}    ${c.dim}(or OPENAI_API_KEY)${c.reset}`);
    }
    console.log();
    console.log(`  ${c.bold}Or use as MCP server${c.reset} in Cursor/Claude ${c.dim}(no extra API key needed):${c.reset}`);
    console.log(`    ${c.dim}Add to your MCP config:${c.reset}`);
    console.log(`    ${c.dim}{ "agentaudit": { "command": "npx", "args": ["-y", "agentaudit"] } }${c.reset}`);
    console.log();
    process.exitCode = 0; return;
  }
  
  // Default no-arg → discover
  const command = args.length === 0 ? 'discover' : args[0];
  const targets = args.slice(1);
  
  banner();
  
  if (command === 'setup') {
    await setupCommand();
    return;
  }
  
  if (command === 'discover') {
    const scanFlag = targets.includes('--quick') || targets.includes('--scan') || targets.includes('-s');
    const auditFlag = targets.includes('--deep') || targets.includes('--audit') || targets.includes('-a');
    await discoverCommand({ scan: scanFlag, audit: auditFlag });
    return;
  }
  
  if (command === 'lookup' || command === 'check') {
    const names = targets.filter(t => !t.startsWith('--'));
    if (names.length === 0) {
      console.log(`  ${c.red}Error: package name required${c.reset}`);
      process.exitCode = 2;
      return;
    }
    const results = [];
    for (const t of names) {
      const data = await checkPackage(t);
      results.push(data);
    }
    if (jsonMode) {
      console.log(JSON.stringify(results.length === 1 ? (results[0] || { error: 'not_found' }) : results, null, 2));
    }
    process.exitCode = 0; return;
    return;
  }
  
  if (command === 'scan') {
    const deepFlag = targets.includes('--deep');
    const urls = targets.filter(t => !t.startsWith('--'));
    if (urls.length === 0) {
      console.log(`  ${c.red}Error: at least one repository URL required${c.reset}`);
      console.log(`  ${c.dim}Tip: use ${c.cyan}agentaudit discover${c.dim} to find & check locally installed MCP servers${c.reset}`);
      console.log(`  ${c.dim}Tip: use ${c.cyan}agentaudit audit <url> --verify self${c.dim} for a deep LLM-powered audit${c.reset}`);
      process.exitCode = 2;
      return;
    }
    
    // --deep redirects to audit flow
    if (deepFlag) {
      let hasFindings = false;
      for (const url of urls) {
        const report = await auditRepo(url);
        if (report?.findings?.length > 0) hasFindings = true;
      }
      process.exitCode = hasFindings ? 1 : 0;
      return;
    }
    
    const results = [];
    let hadErrors = false;
    for (const url of urls) {
      const result = await scanRepo(url);
      if (result) results.push(result);
      else hadErrors = true;
    }
    
    if (jsonMode) {
      const jsonOut = results.map(r => ({
        slug: r.slug,
        url: r.url,
        findings: r.findings.map(f => ({
          severity: f.severity,
          title: f.title,
          file: f.file,
          line: f.line,
          snippet: f.snippet,
        })),
        fileCount: r.files,
        duration: r.duration,
      }));
      console.log(JSON.stringify(jsonOut.length === 1 ? jsonOut[0] : jsonOut, null, 2));
    } else if (results.length > 1) {
      printSummary(results);
    }
    
    if (hadErrors && results.length === 0) { process.exitCode = 2; return; }
    const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
    process.exitCode = totalFindings > 0 ? 1 : 0;
    return;
  }
  
  if (command === 'audit') {
    const urls = targets.filter(t => !t.startsWith('--'));
    if (urls.length === 0) {
      console.log(`  ${c.red}Error: at least one repository URL required${c.reset}`);
      process.exitCode = 2;
      return;
    }
    
    let hasFindings = false;
    for (const url of urls) {
      const report = await auditRepo(url);
      if (report?.findings?.length > 0) hasFindings = true;
    }
    process.exitCode = hasFindings ? 1 : 0;
    return;
  }
  
  console.log(`  ${c.red}Unknown command: ${command}${c.reset}`);
  console.log(`  ${c.dim}Run agentaudit --help for usage${c.reset}`);
  process.exitCode = 2;
}

main().catch(err => {
  console.error(`${c.red}Error: ${err.message}${c.reset}`);
  process.exitCode = 2;
});
