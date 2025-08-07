# Lab 03: Command Argument Validation and Input Sanitization

## Overview

In this lab, you'll enhance the LLM command execution system from [Lab 02](https://github.com/olaekdahl/llm-labs/blob/main/lab-02-llm-guardrails.md) by validating command arguments and sanitizing LLM output before execution.

This is a critical step in securing agentic systems — even when a command is allowed, its *arguments* may be dangerous, irrelevant, or malformed.

[Solution](lab-03-solution.zip)

---

## Learning Objectives

- Parse and validate shell command arguments
- Sanitize LLM-generated command output
- Enforce command-specific safety constraints (e.g., allow `ls /var/log` but not `rm -rf /`)
- Block potentially harmful inputs even if the base command is valid

---

## 🛠 Prerequisites

- Lab 02 completed with LLM + NeMo Guardrails + role-based policy
- Working command validation middleware in Node.js

---

## 🧩 Architecture Extension

```text
User → LLM → Command → NeMo Guardrails (valid command?) → Arg Validator → Execute
```

---

## ✅ Step 1: Add Argument Validation Middleware

Create `validator.ts`:

```ts
const VALID_COMMANDS: Record<string, RegExp> = {
  "ls": /^ls( -[a-zA-Z]+)?( [\w\-/._]+)?$/,
  "df": /^df( -[a-zA-Z]+)?$/,
  "free": /^free( -[a-zA-Z]+)?$/
};

export function validateCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed) return false;

  const base = trimmed.split(" ")[0];
  if (!base) return false;

  const normalized = base.replace(/[^a-z]/g, "");
  const pattern = VALID_COMMANDS[normalized];

  return pattern ? pattern.test(trimmed) : false;
}
```

---

## ✅ Step 2: Call Validator After LLM+NeMo Approval

In `server.ts`:

```ts
import { validateCommand } from './validator.js';

// ...after calling NeMo to validate the command...

if (!validateCommand(command)) {
  return res.status(400).json({ error: "Command format rejected by validator" });
}
```

This ensures:

- Only *approved commands* make it through
- *Only safe argument patterns* are allowed

---

## ✅ Step 3: Test Dangerous Input

Try this user prompt:

> "Show me files in /etc; rm -rf /"

Without validation, the LLM might combine these.
With your regex-based validator:

- `ls /etc` → ✅
- `rm -rf /` → ❌ (not in `VALID_COMMANDS`)
- `ls /etc && whoami` → ❌ (fails regex)

---

## 🔒 Why This Matters

Even in a "trusted" LLM pipeline:

- Users can inject unexpected syntax
- LLMs may misunderstand intent
- Bad arguments = severe consequences

This layer **enforces input discipline** — which OWASP identifies as a cornerstone of secure LLM app design.

---

## References

- [OWASP Securing Agentic Applications](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/)
- [Lab 02: NeMo Guardrails Integration](https://github.com/olaekdahl/llm-labs/blob/main/lab-02-llm-guardrails.md)

---
