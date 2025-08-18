# Lab 05: Trust Boundaries and Escalation Prevention

## Overview

In this lab, you'll extend the secure agent pipeline from [Lab 04](https://github.com/olaekdahl/llm-labs/blob/main/lab-04-secure-tool-chaining-with-memory.md) by explicitly modeling **trust boundaries** and preventing **escalation of privileges**.

Not all tools, memory, or users should be equally trusted. An attacker (or even an overly helpful model) should not be able to cross boundaries — e.g., a "viewer" role requesting an "admin-only" command, or a memory injection leading to higher privileges.

[Solution](lab-05-solution.zip)
---

## Learning Objectives

- Identify trust boundaries in an LLM agent system  
- Enforce *least privilege* for tools, roles, and memory  
- Prevent role escalation or "prompt escalation"  
- Add an "escalation detection" middleware for suspicious requests  

---

## Prerequisites

- Lab 01–04 complete  
- Role-based policies (Lab 01, Lab 04)  
- Argument validation (Lab 03)  
- NeMo Guardrails validation (Lab 02–04)  
- Node.js 20+, TypeScript 5+  

---

## Architecture Extension

```text
User → AuthN/AuthZ → Planner → Tools
        ^          ↘ Escalation checks
        |          
   Role & Trust Boundary
```

- **Boundary enforcement:** Define which roles can cross into which tool domains  
- **Escalation checks:** Detect if a lower-trust role is trying to request higher-trust capabilities  
- **Memory isolation:** Ensure sensitive memory items are scoped to roles that created them  

---

## Step 1: Update `tools.ts` to Define Trust Levels

Open `tools.ts` and update the `Tool` interface and each tool definition.

```ts
// Add new type
export type TrustLevel = "low" | "medium" | "high";

export interface Tool {
  name: ToolName;
  trust: TrustLevel;   // new field
  validate(args?: Record<string, string>): { ok: true } | { ok: false; reason: string };
  run(args?: Record<string, string>): Promise<ToolResult>;
}

// Example updates to tools
const listFiles: Tool = {
  name: "list_files",
  trust: "low",
  validate(args) { ... },
  async run(args) { ... }
};

const diskUsage: Tool = {
  name: "disk_usage",
  trust: "medium",
  validate(args) { ... },
  async run(args) { ... }
};

const readFile: Tool = {
  name: "memory_usage",
  trust: "low",
  validate(args) { ... },
  async run(args) { ... }
};

const readFile: Tool = {
  name: "read_file",
  trust: "high",   // only admins allowed
  validate(args) { ... },
  async run(args) { ... }
};
```

**Why:**  

- Adds a clear **trust level** property to every tool.  
- Makes it explicit which roles can access which tools.  

---

## Step 2: Update `policy.ts` to Map Roles → Trust Levels

Add a new role-trust mapping and check function.

```ts
// Add this mapping
const ROLE_TRUST: Record<string, TrustLevel[]> = {
  admin: ["low", "medium", "high"],
  viewer: ["low", "medium"] // cannot run high-trust tools
};

// New check function
export function checkTrustBoundary(role: string, toolTrust: TrustLevel): PolicyDecision {
  const allowed = ROLE_TRUST[role] || [];
  if (!allowed.includes(toolTrust)) {
    return { ok: false, reason: "Escalation attempt: tool requires higher trust level." };
  }
  return { ok: true };
}
```

**Why:**

- Explicitly enforces **least privilege** by role.  
- Prevents "viewer" from escalating into "admin-only" tools.  

---

## Step 3: Update `server.ts` to Enforce Trust Boundaries

In the `/agent` loop (after fetching the tool implementation from `TOOL_REGISTRY`), add:

```ts
// Add these imports
import jwt from "jsonwebtoken";
import { getMemory, appendMemory, summarizeForPrompt } from "./memory.js";
import { TOOL_REGISTRY, ToolResult, ToolName } from "./tools.js";
import { checkPolicyWithNeMo, checkRoleToken, checkTrustBoundary } from "./policy.js";

import jwt from "jsonwebtoken";
import { summarizeForPrompt, appendMemory, getMemory } from "./src/memory";
import { TOOL_REGISTRY } from "./src/tools";
import { checkRoleToken, checkTrustBoundary } from "./src/policy";
import type { ToolName } from "./src/policy"; // or from tools if you exported it there

app.post("/agent", async (req, res) => {
  try {
    const { query, token, sessionId } = req.body as { query: string; token: string; sessionId?: string };
    const sid = sessionId || "default";

    // Decode token
    let decoded: any;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET as string);
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
    const role = decoded.role as string;

    // Memory summary now requires role
    const summary = summarizeForPrompt(sid, role);

    // (existing) plan with LLM using summary...
    const plan = await planTools(query, summary);

    const results: ToolResult[] = [];
    for (const step of plan.steps) {
      appendMemory(sid, { role: "assistant", content: `Proposed: ${JSON.stringify(step)}`, at: Date.now() });

      const toolName = step.tool as ToolName;

      // Existing RBAC check (optionally returns role if you refactor it)
      const roleDecision = checkRoleToken(token, toolName);
      if (!roleDecision.ok) {
        results.push({ tool: toolName, ok: false, error: roleDecision.reason ?? "" });
        continue;
      }

      // New trust boundary check
      const impl = TOOL_REGISTRY[toolName];
      const trustDecision = checkTrustBoundary(role, impl.trust);
      if (!trustDecision.ok) {
        results.push({ tool: toolName, ok: false, error: trustDecision.reason ?? "" });
        continue;
      }

      // (existing) NeMo policy + arg validation + run...
      // const nemoDecision = await checkPolicyWithNeMo({ tool: toolName, args: step.args ?? {} });
      // if (!nemoDecision.ok) { ... }
      // const argCheck = impl.validate(step.args);
      // if (!argCheck.ok) { ... }
      // const r = await impl.run(step.args);
      // results.push(r);
      // appendMemory(sid, { role: "assistant", content: r.ok ? `Tool ${r.tool} ok` : `Tool ${r.tool} failed: ${r.error ?? ""}`, at: Date.now() });
    }

    appendMemory(sid, { role: "user", content: query, at: Date.now(), /* trust optional */ });
    return res.json({ plan, results, memory: getMemory(sid) });
  } catch (e: any) {
    return res.status(500).json({ error: e?.message || String(e) });
  }
});
```

**Why:**  

- Ensures trust enforcement is applied at runtime for every tool invocation.  

---

## Step 4: Update `memory.ts` for Memory Isolation

Tag memory items with a trust level. Update the interface and summarizer.

```ts
import type { TrustLevel } from "./tools";

export interface MemoryItem {
  role: "user" | "assistant" | "system";
  content: string;
  at: number;
  trust?: TrustLevel;   // new optional trust tag
}

export function summarizeForPrompt(sessionId: string, role: string): string {
  const items = getMemory(sessionId);
  return items
    // filter items based on trust
    .filter(i => {
      if (!i.trust) return true;
      // simple rule: viewer cannot see high-trust memory
      if (role === "viewer" && i.trust === "high") return false;
      return true;
    })
    .map(i => `[${new Date(i.at).toISOString()}] ${i.role}: ${i.content}`)
    .join("\n");
}
```

**Why:**  

- Prevents sensitive memory created in admin sessions from leaking into viewer contexts.  

---

## Step 5: Add Escalation Detection Middleware

In `server.ts`, before planning or executing tools, inspect the query string:

```ts
function detectEscalationAttempt(query: string): boolean {
  const badPatterns = [/sudo/i, /admin/i, /root/i, /elevate/i];
  return badPatterns.some(p => p.test(query));
}

// In /agent route
if (detectEscalationAttempt(query)) {
  return res.status(403).json({ error: "Escalation attempt detected in prompt" });
}
```

**Why:**  

- Adds a lightweight detector for **prompt injection attempts** trying to gain higher privileges.  

---

## Why This Matters

- **Trust boundaries** make privilege separation explicit.  
- **Escalation prevention** ensures a viewer can't become an admin by prompt injection or tool misuse.  
- **Memory isolation** prevents sensitive outputs from leaking across sessions or roles.  

This lab reinforces **OWASP's Agentic Application Guidance**: enforce boundaries, least privilege, and escalation controls. 

---

## References

- [OWASP Securing Agentic Applications Guide](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/)  
- [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)  

---
