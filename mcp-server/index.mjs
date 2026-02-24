#!/usr/bin/env node
/**
 * AgentAudit MCP Server
 * 
 * Security audit capabilities via Model Context Protocol.
 * 
 * Tools:
 *   - discover_servers  Find locally installed MCP servers + check registry status
 *   - audit_package     Clone a repo, return source code + audit prompt for LLM analysis
 *   - submit_report     Upload a completed audit report to agentaudit.dev
 *   - check_package     Look up a package in the AgentAudit registry
 * 
 * Usage:
 *   npx agentaudit                (starts MCP server via stdio)
 *   node index.mjs                (same)
 * 
 * Configure in Claude/Cursor/Windsurf:
 *   { "mcpServers": { "agentaudit": { "command": "npx", "args": ["-y", "agentaudit"] } } }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_DIR = path.resolve(__dirname);
const REGISTRY_URL = 'https://agentaudit.dev';
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
const PRIORITY_FILES = [
  'index.js', 'index.ts', 'index.mjs', 'main.js', 'main.ts', 'main.py',
  'app.js', 'app.ts', 'app.py', 'server.js', 'server.ts', 'server.py',
  'cli.js', 'cli.ts', 'cli.py', '__init__.py', '__main__.py',
  'package.json', 'pyproject.toml', 'setup.py', 'setup.cfg',
  'Cargo.toml', 'go.mod', 'SKILL.md', 'skill.md',
  'Makefile', 'Dockerfile', 'docker-compose.yml',
];

// ── Credentials ─────────────────────────────────────────

function loadApiKey() {
  if (process.env.AGENTAUDIT_API_KEY) return process.env.AGENTAUDIT_API_KEY;
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const xdg = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
  const paths = [
    path.join(SKILL_DIR, 'config', 'credentials.json'),
    path.join(xdg, 'agentaudit', 'credentials.json'),
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) {
      try {
        const key = JSON.parse(fs.readFileSync(p, 'utf8')).api_key;
        if (key) return key;
      } catch {}
    }
  }
  return '';
}

function loadAuditPrompt() {
  const promptPath = path.join(SKILL_DIR, 'prompts', 'audit-prompt.md');
  if (fs.existsSync(promptPath)) return fs.readFileSync(promptPath, 'utf8');
  return 'ERROR: audit-prompt.md not found at ' + promptPath;
}

// ── File Collection ─────────────────────────────────────

function collectFiles(dir, basePath = '', collected = [], totalSize = { bytes: 0 }) {
  if (totalSize.bytes >= MAX_TOTAL_SIZE) return collected;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return collected; }
  entries.sort((a, b) => {
    const aP = PRIORITY_FILES.includes(a.name) ? 0 : 1;
    const bP = PRIORITY_FILES.includes(b.name) ? 0 : 1;
    return aP - bP || a.name.localeCompare(b.name);
  });
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
        if (stat.size > MAX_FILE_SIZE) {
          collected.push({ path: relPath, content: `[FILE TOO LARGE: ${stat.size} bytes — skipped]` });
          continue;
        }
        if (stat.size === 0) continue;
        const content = fs.readFileSync(fullPath, 'utf8');
        totalSize.bytes += content.length;
        collected.push({ path: relPath, content });
      } catch {}
    }
  }
  return collected;
}

// ── Repo Helpers ────────────────────────────────────────

function cloneRepo(sourceUrl) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-'));
  try {
    execSync(`git clone --depth 1 "${sourceUrl}" "${tmpDir}/repo"`, {
      timeout: 30_000, stdio: 'pipe',
    });
    return path.join(tmpDir, 'repo');
  } catch (err) {
    throw new Error(`Failed to clone ${sourceUrl}: ${err.message}`);
  }
}

function cleanupRepo(repoPath) {
  try { fs.rmSync(path.dirname(repoPath), { recursive: true, force: true }); } catch {}
}

function slugFromUrl(url) {
  const match = url.match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (match) return match[2].toLowerCase().replace(/[^a-z0-9-]/g, '-');
  return url.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 60);
}

// ── Discover local MCP configs ──────────────────────────

function discoverMcpServers() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const candidates = [
    { platform: 'Claude Desktop', path: path.join(home, '.claude', 'mcp.json') },
    { platform: 'Claude Desktop', path: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') },
    { platform: 'Claude Desktop', path: path.join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json') },
    { platform: 'Claude Desktop', path: path.join(home, '.config', 'claude', 'claude_desktop_config.json') },
    { platform: 'Cursor', path: path.join(home, '.cursor', 'mcp.json') },
    { platform: 'Windsurf', path: path.join(home, '.codeium', 'windsurf', 'mcp_config.json') },
    { platform: 'VS Code', path: path.join(home, '.vscode', 'mcp.json') },
  ];

  const results = [];

  for (const c of candidates) {
    if (!fs.existsSync(c.path)) {
      results.push({ platform: c.platform, config_path: c.path, status: 'not found', servers: [] });
      continue;
    }
    let content;
    try { content = JSON.parse(fs.readFileSync(c.path, 'utf8')); }
    catch { results.push({ platform: c.platform, config_path: c.path, status: 'parse error', servers: [] }); continue; }

    const serverMap = content.mcpServers || content.servers || {};
    const servers = [];
    for (const [name, cfg] of Object.entries(serverMap)) {
      const allArgs = [cfg.command, ...(cfg.args || [])].filter(Boolean).join(' ');
      const npxMatch = allArgs.match(/npx\s+(?:-y\s+)?(@?[a-z0-9][\w./-]*)/i);
      const pyMatch = allArgs.match(/(?:uvx|pip run|python -m)\s+(@?[a-z0-9][\w./-]*)/i);
      let remoteService = null;
      if (cfg.url) {
        try {
          const hostParts = new URL(cfg.url).hostname.split('.');
          remoteService = hostParts.length === 3 ? hostParts[1] : hostParts[0];
        } catch {}
      }
      servers.push({
        name,
        command: cfg.command || null,
        args: cfg.args || [],
        url: cfg.url || null,
        npm_package: npxMatch?.[1] || null,
        pip_package: pyMatch?.[1] || null,
        remote_service: remoteService,
      });
    }
    results.push({ platform: c.platform, config_path: c.path, status: 'found', server_count: servers.length, servers });
  }

  return results;
}

async function resolveSourceUrl(server) {
  if (server.npm_package) {
    try {
      const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(server.npm_package)}`, {
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
    return `https://www.npmjs.com/package/${server.npm_package}`;
  }
  if (server.pip_package) {
    try {
      const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(server.pip_package)}/json`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = await res.json();
        const urls = data.info?.project_urls || {};
        const source = urls.Source || urls.Repository || urls.Homepage || urls['Source Code'] || data.info?.home_page;
        if (source && source.startsWith('http')) return source;
      }
    } catch {}
    return `https://pypi.org/project/${server.pip_package}/`;
  }
  // URL-based remote MCP — try npm with common naming patterns
  if (server.remote_service) {
    for (const tryName of [
      `@${server.remote_service}/mcp-server-${server.remote_service}`,
      `${server.remote_service}-mcp`,
      `mcp-server-${server.remote_service}`,
    ]) {
      try {
        const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(tryName)}`, {
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const data = await res.json();
          let repoUrl = data.repository?.url;
          if (repoUrl) {
            repoUrl = repoUrl.replace(/^git\+/, '').replace(/\.git$/, '');
            if (repoUrl.startsWith('http')) return repoUrl;
          }
        }
      } catch {}
    }
  }
  return null;
}

async function checkRegistry(slug) {
  try {
    const res = await fetch(`${REGISTRY_URL}/api/skills/${encodeURIComponent(slug)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

// ── MCP Server ───────────────────────────────────────────

const server = new Server(
  { name: 'agentaudit', version: '3.2.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'discover_servers',
      description: 'Find all locally installed MCP servers by scanning config files (Claude Desktop, Cursor, Windsurf, VS Code). Returns the list of configured servers with their names, commands, and package sources. Use this to see what MCP servers are installed, then check each against the registry with check_package, or audit them with audit_package.',
      inputSchema: {
        type: 'object',
        properties: {
          check_registry: {
            type: 'boolean',
            description: 'If true, also check each discovered server against the AgentAudit registry (default: true)',
          },
        },
      },
    },
    {
      name: 'audit_package',
      description: 'Deep security audit: clone a repository and prepare it for LLM-powered analysis. Returns the source code and a 3-pass audit methodology (UNDERSTAND → DETECT → CLASSIFY). You (the agent) then analyze the code following the instructions and call submit_report with your findings. This is a DEEP audit — use check_package first for a quick registry lookup.',
      inputSchema: {
        type: 'object',
        properties: {
          source_url: {
            type: 'string',
            description: 'Git repository URL to audit (e.g., https://github.com/owner/repo)',
          },
        },
        required: ['source_url'],
      },
    },
    {
      name: 'submit_report',
      description: 'Submit a completed security audit report to the AgentAudit registry (agentaudit.dev). Call this after you have analyzed the code from audit_package. The report becomes publicly available and helps other agents make install decisions.',
      inputSchema: {
        type: 'object',
        properties: {
          report: {
            type: 'object',
            description: 'The audit report JSON object. Required fields: skill_slug, source_url, risk_score (0-100), result (safe|caution|unsafe), findings (array), findings_count, max_severity, package_type.',
          },
        },
        required: ['report'],
      },
    },
    {
      name: 'check_package',
      description: 'Quick registry lookup: check if a package has already been audited on agentaudit.dev. Returns the latest audit results (risk score, findings, official status) if available. Use this before audit_package to avoid duplicate work.',
      inputSchema: {
        type: 'object',
        properties: {
          package_name: {
            type: 'string',
            description: 'Package name or slug to look up (e.g., "fastmcp", "mongodb-mcp-server")',
          },
        },
        required: ['package_name'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {

    // ── discover_servers ──────────────────────────────────
    case 'discover_servers': {
      const doRegistryCheck = args.check_registry !== false;
      const configs = discoverMcpServers();
      const foundConfigs = configs.filter(c => c.status === 'found');
      const allServers = foundConfigs.flatMap(c => c.servers.map(s => ({ ...s, platform: c.platform })));

      let text = `# Discovered MCP Servers\n\n`;
      text += `Scanned ${configs.length} config locations. Found ${foundConfigs.length} config(s) with ${allServers.length} server(s).\n\n`;

      for (const config of configs) {
        if (config.status === 'not found') continue;
        text += `## ${config.platform}\n`;
        text += `Config: \`${config.config_path}\`\n\n`;

        if (config.servers.length === 0) {
          text += `No servers configured.\n\n`;
          continue;
        }

        for (const srv of config.servers) {
          const slug = srv.npm_package?.replace(/^@/, '').replace(/\//g, '-')
            || srv.pip_package?.replace(/[^a-z0-9-]/gi, '-')
            || srv.name.toLowerCase().replace(/[^a-z0-9-]/gi, '-');

          text += `### ${srv.name}\n`;
          if (srv.url) {
            text += `- URL: \`${srv.url}\`\n`;
          } else {
            text += `- Command: \`${[srv.command, ...srv.args].filter(Boolean).join(' ')}\`\n`;
          }
          if (srv.npm_package) text += `- npm: ${srv.npm_package}\n`;
          if (srv.pip_package) text += `- pip: ${srv.pip_package}\n`;
          if (srv.remote_service) text += `- Service: ${srv.remote_service}\n`;

          if (doRegistryCheck) {
            const regData = await checkRegistry(slug);
            if (regData) {
              const risk = regData.risk_score ?? regData.latest_risk_score ?? 0;
              const official = regData.has_official_audit ? ' (official)' : '';
              text += `- **Registry: ✅ Audited** — Risk ${risk}/100${official}\n`;
              text += `- Report: ${REGISTRY_URL}/skills/${slug}\n`;
            } else {
              const sourceUrl = await resolveSourceUrl(srv);
              text += `- **Registry: ⚠️ Not audited** — no audit report found\n`;
              if (sourceUrl) {
                text += `- Source: ${sourceUrl}\n`;
                text += `- To audit: call \`audit_package\` with source_url \`${sourceUrl}\`\n`;
              } else {
                text += `- Source URL unknown — check the package's GitHub/npm page\n`;
                text += `- To audit: find the source URL, then call \`audit_package\`\n`;
              }
            }
          }
          text += `\n`;
        }
      }

      if (allServers.length === 0) {
        text += `No MCP servers found. Config locations searched:\n`;
        text += `- Claude Desktop: ~/.claude/mcp.json\n`;
        text += `- Cursor: ~/.cursor/mcp.json\n`;
        text += `- Windsurf: ~/.codeium/windsurf/mcp_config.json\n`;
        text += `- VS Code: ~/.vscode/mcp.json\n`;
      }

      return { content: [{ type: 'text', text }] };
    }

    // ── audit_package ─────────────────────────────────────
    case 'audit_package': {
      const { source_url } = args;
      if (!source_url || !source_url.startsWith('http')) {
        return { content: [{ type: 'text', text: 'Error: source_url must be a valid HTTP(S) URL' }] };
      }

      let repoPath;
      try {
        repoPath = cloneRepo(source_url);
        const files = collectFiles(repoPath);
        const slug = slugFromUrl(source_url);
        const auditPrompt = loadAuditPrompt();

        let codeBlock = '';
        for (const file of files) {
          codeBlock += `\n### FILE: ${file.path}\n\`\`\`\n${file.content}\n\`\`\`\n`;
        }

        const response = [
          `# Security Audit: ${slug}`,
          ``,
          `**Source:** ${source_url}`,
          `**Files collected:** ${files.length}`,
          ``,
          `## Your Task`,
          ``,
          `1. Analyze the source code below using the 3-pass audit methodology`,
          `2. Call \`submit_report\` with your findings as JSON`,
          ``,
          `## Report Format`,
          ``,
          `Your report JSON must include:`,
          '```json',
          `{`,
          `  "skill_slug": "${slug}",`,
          `  "source_url": "${source_url}",`,
          `  "package_type": "<mcp-server|agent-skill|library|cli-tool>",`,
          `  "risk_score": <0-100>,`,
          `  "result": "<safe|caution|unsafe>",`,
          `  "max_severity": "<none|low|medium|high|critical>",`,
          `  "findings_count": <number>,`,
          `  "findings": [`,
          `    {`,
          `      "id": "FINDING_ID",`,
          `      "title": "Short title",`,
          `      "severity": "<low|medium|high|critical>",`,
          `      "category": "<category>",`,
          `      "description": "Detailed description",`,
          `      "file": "path/to/file.js",`,
          `      "line": <line_number>,`,
          `      "remediation": "How to fix",`,
          `      "confidence": "<low|medium|high>",`,
          `      "is_by_design": <true|false>`,
          `    }`,
          `  ]`,
          `}`,
          '```',
          ``,
          `## Audit Methodology`,
          ``,
          auditPrompt,
          ``,
          `## Source Code`,
          ``,
          codeBlock,
        ].join('\n');

        return { content: [{ type: 'text', text: response }] };
      } catch (err) {
        return { content: [{ type: 'text', text: `Error: ${err.message}` }] };
      } finally {
        if (repoPath) cleanupRepo(repoPath);
      }
    }

    // ── submit_report ─────────────────────────────────────
    case 'submit_report': {
      const { report } = args;
      if (!report || typeof report !== 'object') {
        return { content: [{ type: 'text', text: 'Error: report must be a JSON object' }] };
      }

      const apiKey = loadApiKey();
      if (!apiKey) {
        return { content: [{ type: 'text', text: 'Error: No API key configured. Run `npx agentaudit setup` or set AGENTAUDIT_API_KEY.' }] };
      }

      const required = ['skill_slug', 'source_url', 'risk_score', 'result'];
      for (const field of required) {
        if (report[field] == null) {
          return { content: [{ type: 'text', text: `Error: Missing required field "${field}" in report` }] };
        }
      }

      if (!Array.isArray(report.findings)) report.findings = [];
      report.findings_count = report.findings.length;
      if (!report.max_severity) {
        const severities = ['critical', 'high', 'medium', 'low', 'none'];
        report.max_severity = report.findings.reduce((max, f) => {
          const fi = severities.indexOf(f.severity);
          const mi = severities.indexOf(max);
          return fi < mi ? f.severity : max;
        }, 'none');
      }

      try {
        const res = await fetch(`${REGISTRY_URL}/api/reports`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(report),
          signal: AbortSignal.timeout(60_000),
        });

        const body = await res.text();
        let data;
        try { data = JSON.parse(body); } catch { data = { raw: body }; }

        if (res.ok) {
          return { content: [{ type: 'text', text: `✅ Report submitted!\n\nReport ID: ${data.report_id || 'unknown'}\nURL: ${REGISTRY_URL}/skills/${report.skill_slug}\nRisk: ${report.risk_score}/100 (${report.result})\nFindings: ${report.findings_count}` }] };
        } else {
          return { content: [{ type: 'text', text: `Upload failed (HTTP ${res.status}): ${JSON.stringify(data, null, 2)}` }] };
        }
      } catch (err) {
        return { content: [{ type: 'text', text: `Upload error: ${err.message}` }] };
      }
    }

    // ── check_package ─────────────────────────────────────
    case 'check_package': {
      const { package_name } = args;
      if (!package_name) {
        return { content: [{ type: 'text', text: 'Error: package_name is required' }] };
      }

      try {
        const res = await fetch(`${REGISTRY_URL}/api/skills/${encodeURIComponent(package_name)}`, {
          signal: AbortSignal.timeout(10_000),
        });

        if (res.status === 404) {
          return { content: [{ type: 'text', text: `Package "${package_name}" not found in registry.\n\nIt hasn't been audited yet. To audit it:\n1. Find the source URL (GitHub repo)\n2. Call audit_package with the URL\n3. Analyze the code\n4. Call submit_report with your findings` }] };
        }

        const data = await res.json();
        const risk = data.risk_score ?? data.latest_risk_score ?? 'unknown';
        const official = data.has_official_audit ? '✅ Officially audited' : 'Community audit';

        let summary = `# ${package_name}\n\n`;
        summary += `**Risk Score:** ${risk}/100\n`;
        summary += `**Status:** ${official}\n`;
        if (data.source_url) summary += `**Source:** ${data.source_url}\n`;
        summary += `**Registry:** ${REGISTRY_URL}/skills/${package_name}\n\n`;
        summary += `## Full Data\n\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\``;

        return { content: [{ type: 'text', text: summary }] };
      } catch (err) {
        return { content: [{ type: 'text', text: `Registry lookup failed: ${err.message}` }] };
      }
    }

    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${name}. Available: discover_servers, audit_package, submit_report, check_package` }] };
  }
});

// ── Start ────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
