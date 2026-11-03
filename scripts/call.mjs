// Llama una herramienta del MCP desde la terminal, sin cliente MCP:
//   node scripts/call.mjs scan_static '{"path":"C:/proyecto"}'
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

const [name, json = "{}"] = process.argv.slice(2);
if (!name) {
  console.error("uso: node scripts/call.mjs <herramienta> '<json de argumentos>'");
  process.exit(2);
}
const here = path.dirname(fileURLToPath(import.meta.url));
const client = new Client({ name: "call", version: "0.0.0" });
await client.connect(new StdioClientTransport({ command: process.execPath, args: [path.join(here, "..", "dist", "index.js")] }));
const r = await client.callTool({ name, arguments: JSON.parse(json) }, undefined, { timeout: 6 * 60 * 60_000, resetTimeoutOnProgress: true });
console.log(r.content.map((c) => c.text).join("\n"));
await client.close();
process.exit(r.isError ? 1 : 0);
