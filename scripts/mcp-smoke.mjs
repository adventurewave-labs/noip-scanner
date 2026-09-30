// Spawns `noip mcp` over real stdio and calls tools/list + a demo scan through the official MCP client.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const client = new Client({ name: 'noip-ci-smoke', version: '0' });
await client.connect(new StdioClientTransport({ command: process.execPath, args: ['--no-deprecation', 'dist/cli.js', 'mcp', '--no-ignore'] }));
const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort().join(',');
if (names !== 'admission_policy,explain_finding,list_checks,pod_security_readiness,risk_chains,scan') throw new Error(`unexpected tools: ${names}`);
const res = await client.callTool({ name: 'scan', arguments: { demo: true, minSeverity: 'critical' } });
if (res.isError || res.structuredContent?.source !== 'demo') throw new Error(`scan failed: ${JSON.stringify(res).slice(0, 300)}`);
console.log(`mcp smoke: tools=[${names}] demo critical findings=${res.structuredContent.findings.length}`);
await client.close();
