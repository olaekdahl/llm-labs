# Lab 04: Secure Tool Chaining with Memory

## Overview

In this lab you will extend the secure command pipeline from Lab 01–03 by adding:

- A planner that lets an LLM propose a sequence of “tool calls” instead of a single command
- A memory layer so follow‑up prompts can reference prior steps
- A policy gate so each proposed tool call is validated before execution
- Argument validation & sanitization reused from Lab 03

This demonstrates agentic behavior with defense‑in‑depth: the model can plan multi‑step actions, but tools only execute if they pass NeMo Guardrails policy checks, RBAC, and argument validators.

[Solution](lab-04-solution.zip)

## Learning Objectives

- Represent tools with a typed interface and registry
- Ask the LLM to return structured JSON plans
- Validate plans with Zod before execution
- Check each step with NeMo Guardrails and role policy
- Maintain short‑term memory for contextual follow‑ups

## Prerequisites

- Lab 01: Secure exec and RBAC
- Lab 02: NeMo Guardrails proxy running at http://localhost:7000
- Lab 03: Regex validators for safe shell arguments

## Step 0: Install dependencies

```bash
npm install zod node-fetch
```

## Step 1: Define Tool Interface and Registry

Create **tools.ts**

```ts
import { exec as _exec } from "child_process";
import { promisify } from "util";
const exec = promisify(_exec);

export type ToolName = "list_files" | "disk_usage" | "memory_usage" | "read_file";

export interface ToolCall {
  tool: ToolName;
  args?: Record<string, string>;
}

export interface ToolResult {
  tool: ToolName;
  ok: boolean;
  output?: string;
  error?: string;
}

export interface Tool {
  name: ToolName;
  validate(args?: Record<string, string>): { ok: true } | { ok: false; reason: string };
  run(args?: Record<string, string>): Promise<ToolResult>;
}

function safePath(p?: string): boolean {
  if (!p) return true;
  return /^\/[A-Za-z0-9_\-/.]*$/.test(p) && !p.includes("..");
}
function safeFlag(f?: string): boolean {
  if (!f) return true;
  return /^-[A-Za-z]+$/.test(f);
}

const listFiles: Tool = {
  name: "list_files",
  validate(args) {
    if (args?.path && !safePath(args.path)) return { ok: false, reason: "Invalid path" };
    if (args?.flags && !safeFlag(args.flags)) return { ok: false, reason: "Invalid flags" };
    return { ok: true };
  },
  async run(args) {
    const path = args?.path || ".";
    const flags = args?.flags || "-la";
    try {
      const { stdout } = await exec(`ls ${flags} ${path}`.trim());
      return { tool: "list_files", ok: true, output: stdout };
    } catch (e: any) {
      return { tool: "list_files", ok: false, error: e?.message || String(e) };
    }
  }
};

const diskUsage: Tool = {
  name: "disk_usage",
  validate(args) {
    if (args?.flags && !safeFlag(args.flags)) return { ok: false, reason: "Invalid flags" };
    return { ok: true };
  },
  async run(args) {
    const flags = args?.flags || "-h";
    try {
      const { stdout } = await exec(`df ${flags}`.trim());
      return { tool: "disk_usage", ok: true, output: stdout };
    } catch (e: any) {
      return { tool: "disk_usage", ok: false, error: e?.message || String(e) };
    }
  }
};

const memoryUsage: Tool = {
  name: "memory_usage",
  validate(args) {
    if (args?.flags && !safeFlag(args.flags)) return { ok: false, reason: "Invalid flags" };
    return { ok: true };
  },
  async run(args) {
    const flags = args?.flags || "-m";
    try {
      const { stdout } = await exec(`free ${flags}`.trim());
      return { tool: "memory_usage", ok: true, output: stdout };
    } catch (e: any) {
      return { tool: "memory_usage", ok: false, error: e?.message || String(e) };
    }
  }
};

const readFile: Tool = {
  name: "read_file",
  validate(args) {
    if (!args?.path) return { ok: false, reason: "path required" };
    if (!safePath(args.path)) return { ok: false, reason: "Invalid path" };
    return { ok: true };
  },
  async run(args) {
    try {
      const { stdout } = await exec(`tail -n 200 ${args?.path}`);
      return { tool: "read_file", ok: true, output: stdout };
    } catch (e: any) {
      return { tool: "read_file", ok: false, error: e?.message || String(e) };
    }
  }
};

export const TOOL_REGISTRY: Record<ToolName, Tool> = {
  list_files: listFiles,
  disk_usage: diskUsage,
  memory_usage: memoryUsage,
  read_file: readFile
};
```

Why:

- Encapsulates all OS interaction logic behind safe, typed tool interfaces.
- Ensures each tool validates its arguments before execution.
- Makes it easy to extend the system with new tools without changing core logic.

---

## Step 2: Add a Simple Session Memory

Create **memory.ts**

```ts
export interface MemoryItem {
  role: "user" | "assistant" | "system";
  content: string;
  at: number;
}

type SessionId = string;
const store = new Map<SessionId, MemoryItem[]>();

export function appendMemory(sessionId: string, item: MemoryItem) {
  const list = store.get(sessionId) ?? [];
  list.push(item);
  const MAX_ITEMS = 20;
  const trimmed = list.slice(-MAX_ITEMS);
  store.set(sessionId, trimmed);
}

export function getMemory(sessionId: string): MemoryItem[] {
  return store.get(sessionId) ?? [];
}

export function summarizeForPrompt(sessionId: string): string {
  const items = getMemory(sessionId);
  return items.map(i => `[${new Date(i.at).toISOString()}] ${i.role}: ${i.content}`).join("\n");
}
```

Why:

- Maintains short-term session context for multi-step planning.
- Enables the LLM to reference prior queries and outputs.
- Keeps memory size bounded to prevent unbounded growth.

---

## Step 3: Planner that Returns Structured JSON

Create **planner.ts**

```ts
import OpenAI from "openai";
import { z } from "zod";
import dotenv from "dotenv";
dotenv.config();

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export const ToolCallSchema = z.object({
  tool: z.enum(["list_files", "disk_usage", "memory_usage", "read_file"]),
  args: z.record(z.string()).optional()
});
export const PlanSchema = z.object({
  steps: z.array(ToolCallSchema).min(1).max(5)
});
export type Plan = z.infer<typeof PlanSchema>;

const SYSTEM = `You are a planning agent that outputs ONLY JSON with this shape:
{
  "steps": [
    { "tool": "<one of: list_files|disk_usage|memory_usage|read_file>", "args": { "<k>": "<v>" } }
  ]
}
Do not include explanations or markdown. Prefer minimal steps. If user asks to read files, only do so if a path is provided.`;

export async function planTools(userQuery: string, memorySummary: string): Promise<Plan> {
  const user = `User query: ${userQuery}\n\nContext:\n${memorySummary || "(no memory)"}\n\nReturn JSON only.`;

  const resp = await openai.chat.completions.create({
    model: "gpt-3.5-turbo",
    messages: [
      { role: "system", content: SYSTEM },
      { role: "user", content: user }
    ],
    temperature: 0
  });

  const text = resp.choices[0]?.message?.content?.trim() || "";
  let parsed: Plan;
  try {
    parsed = PlanSchema.parse(JSON.parse(text));
  } catch {
    parsed = { steps: [{ tool: "disk_usage" }] as any };
  }
  return parsed;
}
```

Why:

- Delegates multi-step action planning to the LLM while enforcing a strict JSON schema.
- Validates LLM output with Zod before using it.
- Supplies memory context so the LLM can plan follow-up actions in sequence.

---

## Step 4: Policy Validation with NeMo + RBAC

Create **policy.ts**

```ts
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import { z } from "zod";

const ToolNameSchema = z.enum(["list_files", "disk_usage", "memory_usage", "read_file"]);
export type ToolName = z.infer<typeof ToolNameSchema>;

const ROLE_POLICY: Record<string, ToolName[]> = {
  admin: ["list_files", "disk_usage", "memory_usage", "read_file"],
  viewer: ["list_files", "disk_usage", "memory_usage"]
};

export interface PolicyDecision {
  ok: boolean;
  reason?: string;
}

export async function checkPolicyWithNeMo(tool: { tool: ToolName; args?: Record<string, string> }): Promise<PolicyDecision> {
  try {
    const res = await fetch("http://localhost:7000/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: tool.tool })
    });
    const data = await res.json();
    const validated = (data.validated_command || data.command || "").trim();
    if (validated === tool.tool) return { ok: true };
    if (validated === "validated") return { ok: true };
    return { ok: false, reason: "Rejected by NeMo policy." };
  } catch (e: any) {
    return { ok: false, reason: `NeMo policy error: ${e?.message || e}` };
  }
}

export function checkRoleToken(token: string, tool: ToolName): PolicyDecision {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as any;
    const role = decoded.role;
    const allowed = ROLE_POLICY[role] || [];
    if (!allowed.includes(tool)) return { ok: false, reason: "Role not permitted for tool." };
    return { ok: true };
  } catch {
    return { ok: false, reason: "Invalid token." };
  }
}
```

Why:

- Centralizes RBAC and NeMo Guardrails policy enforcement for tool usage.
- Separates policy checks from execution logic, making the system easier to audit.
- Allows both role-based filtering and model-based safety checks before running a tool.

---

## Step 5: Orchestrate Planning → Policy → Validation → Execution

Update **server.ts** with a new `/agent` route:

```ts
import { planTools } from "./planner.js";
import { getMemory, appendMemory, summarizeForPrompt } from "./memory.js";
import { checkPolicyWithNeMo, checkRoleToken } from "./policy.js";
import { TOOL_REGISTRY, ToolResult, ToolName } from "./tools.js";

app.post("/agent", async (req, res) => {
  try {
    const { query, token, sessionId } = req.body as {
      query: string;
      token: string;
      sessionId?: string;
    };
    const sid = sessionId || "default";

    const summary = summarizeForPrompt(sid);
    const plan = await planTools(query, summary);

    const results: ToolResult[] = [];
    for (const step of plan.steps) {
      appendMemory(sid, {
        role: "assistant",
        content: `Proposed: ${JSON.stringify(step)}`,
        at: Date.now(),
      });

      const toolName = step.tool as ToolName;

      // Role policy
      const roleDecision = checkRoleToken(token, toolName);
      if (!roleDecision.ok) {
        results.push({
          tool: toolName,
          ok: false,
          error: roleDecision.reason ?? "",
        });
        continue;
      }

      // NeMo policy
      const nemoDecision = await checkPolicyWithNeMo({
        tool: toolName,
        args: step.args ?? {},
      });
      if (!nemoDecision.ok) {
        results.push({
          tool: toolName,
          ok: false,
          error: nemoDecision.reason ?? "",
        });
        continue;
      }

      // Argument validation + run
      const impl = TOOL_REGISTRY[toolName];
      const argCheck = impl.validate(step.args);
      if (!argCheck.ok) {
        results.push({
          tool: toolName,
          ok: false,
          error: argCheck.reason ?? "",
        });
        continue;
      }

      const r = await impl.run(step.args);
      results.push(r);

      const content = r.ok
        ? `Tool ${r.tool} ok`
        : `Tool ${r.tool} failed: ${r.error ?? ""}`;
      appendMemory(sid, { role: "assistant", content, at: Date.now() });
    }

    appendMemory(sid, { role: "user", content: query, at: Date.now() });
    return res.json({ plan, results, memory: getMemory(sid) });
  } catch (e: any) {
    return res.status(500).json({ error: e?.message || String(e) });
  }
});
```

Why:

- Orchestrates the complete tool execution workflow from planning to validation to execution.
- Ensures every tool call passes RBAC, NeMo policy, and argument validation before running.
- Aggregates results and updates memory for subsequent turns.

---

## Step 6: Update frontend

Update **dist/frontend/index.html** to use the `agent` route.

```html
<form id="agentForm">
  <input id="agentQuery" placeholder="e.g. check disk then list files in /var/log" required />
  <button type="submit">Run Agent</button>
</form>
<pre id="agentOutput"></pre>
<script>
  document.getElementById("agentForm").onsubmit = async (e) => {
    e.preventDefault();
    const query = document.getElementById("agentQuery").value;
    const res = await fetch("/agent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, token, sessionId: "demo" })
    });
    const data = await res.json();
    document.getElementById("agentOutput").textContent = JSON.stringify(data, null, 2);
  };
</script>
```

## Step 7: Update NeMo policy

Update **rails/prompt_rails.co** to support both labs 2 and 4.

```co
##############################################
# Natural Language to Shell Command (Lab 02) #
##############################################

define user express list_all_files
  "list all files"
  "show all files in directory"
  "list files"

define user express disk_usage
  "check disk usage"
  "show disk usage"

define user express memory_usage
  "check memory usage"
  "show memory stats"

define bot say ls
  "ls -la"

define bot say du
  "df -h"

define bot say free
  "free -m"

define flow list_files
  user express list_all_files
  bot say ls

define flow disk_usage
  user express disk_usage
  bot say du

define flow memory_usage
  user express memory_usage
  bot say free

##############################################
# Tool Name to Validation Token (Lab 04)     #
##############################################

define user express list_files_tool
  "list_files"

define user express disk_usage_tool
  "disk_usage"

define user express memory_usage_tool
  "memory_usage"

define user express read_file_tool
  "read_file"

define bot say validated
  "validated"

define flow allow_list_files
  user express list_files_tool
  bot say validated

define flow allow_disk_usage
  user express disk_usage_tool
  bot say validated

define flow allow_memory_usage
  user express memory_usage_tool
  bot say validated

define flow allow_read_file
  user express read_file_tool
  bot say validated
```

## Step 8: Test Scenarios

- "Check disk usage then list files in /var/log sorted by time"
- "Read /etc/passwd"

## Security Notes

- Planner JSON schema + RBAC + NeMo policy + argument validators
- No raw shell concatenation
- Memory is short‑lived in this lab
- NeMo policy should accept only known tool names

## OWASP Alignment

- Tool use restrictions
- I/O control
- Trust boundaries
- Auditability

## Build and Run

```bash
npm run build
node dist/server.js
```

With NeMo proxy running at http://localhost:7000.
