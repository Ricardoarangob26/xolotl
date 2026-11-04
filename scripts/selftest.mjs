// Prueba de punta a punta: levanta el servidor por stdio como lo haría Claude y escanea
// un proyecto vulnerable generado al vuelo (el token falso se arma en tiempo de ejecución
// para que el propio repo no contenga secretos).
//   node scripts/selftest.mjs            → doctor + escaneo + informe
//   node scripts/selftest.mjs --install  → instala antes los escáneres que falten
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(os.tmpdir(), "xolotl-selftest");
fs.rmSync(fixture, { recursive: true, force: true });
fs.mkdirSync(fixture, { recursive: true });

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const fakeToken = "ghp_" + Array.from(crypto.randomBytes(36), (b) => alnum[b % alnum.length]).join("");

const files = {
  "app.py": `import subprocess, yaml, hashlib
from flask import Flask, request
app = Flask(__name__)

@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    return subprocess.check_output(cmd, shell=True)

@app.route("/load")
def load():
    return str(yaml.load(request.data))

def weak(p):
    return hashlib.md5(p.encode()).hexdigest()
`,
  "server.js": `const express = require("express");
const { exec } = require("child_process");
const app = express();
app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});
app.get("/calc", (req, res) => res.send(String(eval(req.query.expr))));
app.listen(3000);
`,
  "config.js": `module.exports = { githubToken: "${fakeToken}" };\n`,
  "requirements.txt": "django==2.2.0\npyyaml==5.3\n",
  "package.json": JSON.stringify({ name: "selftest", version: "1.0.0", dependencies: { lodash: "4.17.15" } }, null, 2),
  "package-lock.json": JSON.stringify(
    {
      name: "selftest",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "selftest", version: "1.0.0", dependencies: { lodash: "4.17.15" } },
        "node_modules/lodash": {
          version: "4.17.15",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
          integrity: "sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==",
        },
      },
    },
    null,
    2,
  ),
  Dockerfile: "FROM node:latest\nCOPY . /app\nRUN npm install\nCMD [\"node\", \"/app/server.js\"]\n",
};
for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(fixture, name), body);

// HOME aislado para datos (inventario, corridas, alcance), reutilizando los binarios ya
// instalados: el autotest no debe ensuciar el inventario ni las corridas reales del usuario.
const sandboxHome = path.join(fixture, ".xolotl-home");
const realTools = path.join(os.homedir(), ".xolotl", "tools");
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(here, "..", "dist", "index.js")],
  env: { ...process.env, XOLOTL_HOME: sandboxHome, XOLOTL_TOOLS: process.env.XOLOTL_TOOLS ?? realTools },
  stderr: "inherit",
});
const client = new Client({ name: "selftest", version: "0.0.0" });
await client.connect(transport);

const call = async (name, args = {}) => {
  const started = Date.now();
  const r = await client.callTool({ name, arguments: args }, undefined, { timeout: 60 * 60_000, resetTimeoutOnProgress: true });
  const body = r.content.map((c) => c.text).join("\n");
  console.log(`\n━━━ ${name} (${((Date.now() - started) / 1000).toFixed(1)}s)${r.isError ? " ERROR" : ""} ━━━\n${body}`);
  return body;
};

const { tools } = await client.listTools();
const { prompts } = await client.listPrompts();
console.log(`Herramientas: ${tools.map((t) => t.name).join(", ")}\nPrompts: ${prompts.map((p) => p.name).join(", ")}`);

if (process.argv.includes("--install")) await call("xolotl_install", { tools: ["trivy", "gitleaks", "osv-scanner", "nuclei"] });
await call("xolotl_doctor");
await call("scan_static", { path: fixture });
await call("findings_query", { min_severity: "high" });
await call("finding_get", { finding_id: "F-001", context_lines: 3 });
await call("scan_dast", { targets: ["https://example.com"] }); // debe negarse: fuera de alcance
await call("report_generate", { format: "md" });
await call("report_generate", { format: "sarif" });
await client.close();
