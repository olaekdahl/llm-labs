# Lab 01: Secure LLM-Driven Command Execution with Role-Based Access

## Overview

In this lab, you'll build a secure, AI-powered command execution app that transforms natural language queries into Linux shell commands using OpenAI's GPT models. You'll implement role-based access control with JWTs and provide a web frontend with user login, command suggestions, and output rendering.

---

## 🧱 Architecture

```text
User → Login → Token → Query → LLM → Command → Policy Check → Execute → Result
```

---

## Lab Goals

1. Integrate OpenAI's GPT to translate queries to commands
2. Create a secure backend with:
   - JWT-based authentication
   - Role-based access control
   - Command whitelisting
   - Audit logging
3. Build a simple HTML frontend with:
   - Login
   - Command suggestions per role
   - Real-time query execution

---

## 🛠 Prerequisites

- Node.js 20+
- OpenAI API key
- Basic Linux shell familiarity

---

## 📁 Folder Structure

```text
llm-secure-exec-demo/
├── auth.ts                   # Login, JWT, audit logging, role policies
├── server.ts                 # Express API routes
├── llm.ts                    # OpenAI integration
├── executor.ts               # Shell command execution
├── dist/frontend/index.html  # UI with login and command form
├── .env                      # Secrets (OpenAI key, JWT secret)
└── tsconfig.json
```

---

## 🧪 Step 1: Initialize the Project

```bash
mkdir llm-secure-exec-demo && cd llm-secure-exec-demo
npm init -y
npm install express openai dotenv jsonwebtoken
npm install --save-dev @types/jsonwebtoken
npm install --save-dev @types/express
npm install --save-dev typescript ts-node
npx tsc --init
```

This project uses **ES Modules** (ESM) syntax like `import express from 'express'`. To make sure your TypeScript and Node environment supports this:

### 🔧 tsconfig.json

Update or create `tsconfig.json` with these values:

```json
{
  "compilerOptions": {
    "outDir": "./dist",
    "module": "ESNext",
    "target": "ES2020",
    "moduleResolution": "node",
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "strict": true,
    "skipLibCheck": true,
    "verbatimModuleSyntax": false
  },
  "include": ["*.ts"]
}
```

### 🔧 package.json

Make sure your `package.json` includes:

```json
{
  "type": "module"
}
```

---

## 🔐 Step 2: Implement Authentication and Policy Engine

Create `auth.ts`:

```ts
import jwt from 'jsonwebtoken';
import { promises as fs } from 'fs';

const policyDB: Record<string, string[]> = {
  'admin': ['ls -a','ls -la', 'df -h'],
  'viewer': ['ls -a', 'ls -la'],
};

const auditLogPath = './audit.log';

export async function validateTokenAndPermissions(token: string, command: string) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as any;
    const role = decoded.role;
    const allowedCommands = policyDB[role] || [];

    const normalizedCommand = command.trim();
    const allowed = allowedCommands.includes(normalizedCommand);

    const entry = `[${new Date().toISOString()}] role=${role} command="${command}" allowed=${allowed}\n`;
    await fs.appendFile(auditLogPath, entry);

    console.log("Decoded role:", role);
    console.log("Command from LLM:", JSON.stringify(command));
    console.log("Allowed commands:", allowedCommands);

    if (!allowed) {
      return { valid: false, reason: 'Insufficient permissions' };
    }

    return { valid: true, reason: 'Allowed command' };
  } catch (err) {
    return { valid: false, reason: 'Invalid or expired token' };
  }
}

export function login(username: string, password: string): string | null {
  const users: Record<string, { password: string, role: string }> = {
    alice: { password: "pass123", role: "admin" },
    bob: { password: "pass123", role: "viewer" }
  };

  const user = users[username];
  if (user && user.password === password) {
    return jwt.sign({ role: user.role }, process.env.JWT_SECRET as string, { expiresIn: "1h" });
  }

  return null;
}
```

Why:

- Centralizes logic for authentication, policy enforcement, and audit logging.

---

## 🤖 Step 3: Implement LLM Integration

Create `llm.ts`:

```ts
iimport OpenAI from "openai";
import dotenv from "dotenv";

dotenv.config();

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

export async function getCommandFromLLM(query: string, token: string): Promise<string | null> {
  const prompt = `Translate this user query into a Linux command: "${query}"`;
  const response = await openai.chat.completions.create({
  model: "gpt-3.5-turbo",
  messages: [
    { role: "system", content: "You are a system that translates natural language into raw Linux shell commands. Respond with only the command and nothing else. Do not include explanations, Markdown, or formatting." },
    { role: "user", content: `Translate this user query into a Linux command: "${prompt}"` }
  ],
  max_tokens: 30,
  temperature: 0,
});


  const command = response.choices[0]?.message?.content?.trim();
  return command || null;
}
```

Why:

- Uses GPT to convert user intent into commands safely with token constraints.

---

## ⚙️ Step 4: Implement Secure Command Execution

Create `executor.ts`:

```ts
import { exec } from 'child_process';
import util from 'util';

const execAsync = util.promisify(exec);

export async function executeCommand(command: string): Promise<string> {
  try {
    const { stdout } = await execAsync(command);
    return stdout;
  } catch (err) {
    return 'Command failed';
  }
}
```

Why:

- Prevents shell injection and isolates command execution logic.

---

## 🌐 Step 5: Build Express Server

Create `server.ts`:

```ts
import express from 'express';
import { getCommandFromLLM } from './llm.js';
import { validateTokenAndPermissions, login } from './auth.js';
import { executeCommand } from './executor.js';

const app = express();
app.use(express.json());
app.use(express.static("frontend"));

app.post('/query', async (req, res) => {
  const { query, token } = req.body;
  const command = await getCommandFromLLM(query, token);
  if (!command) return res.status(400).send('Could not parse query');

  const { valid, reason } = await validateTokenAndPermissions(token, command);
  if (!valid) return res.status(403).send(`Unauthorized: ${reason}`);

  const output = await executeCommand(command);
  return res.json({ output });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const token = login(username, password);
  if (!token) return res.status(401).send('Invalid credentials');
  return res.json({ token });
});

app.listen(3000, () => console.log('LLM Secure Exec running on http://localhost:3000'));
```

Why:

- Defines secure API entrypoints for login and command execution.

---

## 💻 Step 6: Create Frontend

Create `dist/frontend/index.html`:

```html
<!DOCTYPE html>
<html>
<head><title>LLM Secure Exec</title></head>
<body>
  <h1>Login</h1>
  <form id="loginForm">
    <input id="username" placeholder="Username" required>
    <input id="password" placeholder="Password" type="password" required>
    <button type="submit">Login</button>
  </form>

  <div id="commandSection" style="display:none;">
    <h2>Command Query</h2>
    <p id="roleHint"></p>
    <form id="queryForm">
      <input id="query" placeholder="e.g. list all files" required>
      <button type="submit">Send</button>
    </form>
    <ul id="suggestions"></ul>
    <pre id="output"></pre>
  </div>

  <script>
    let token = "";
    const policies = {
      admin: ["ls -a", "ls -la", "df -h"],
      viewer: ["ls -a", "ls -la"]
    };

    document.getElementById("loginForm").onsubmit = async (e) => {
      e.preventDefault();
      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;

      const res = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      token = data.token;
      const role = JSON.parse(atob(token.split('.')[1])).role;

      document.getElementById("roleHint").textContent = "Role: " + role;
      const list = document.getElementById("suggestions");
      list.innerHTML = "";
      policies[role].forEach(cmd => {
        const li = document.createElement("li");
        li.textContent = cmd;
        list.appendChild(li);
      });

      document.getElementById("commandSection").style.display = "block";
    };

    document.getElementById("queryForm").onsubmit = async (e) => {
      e.preventDefault();
      const query = document.getElementById("query").value;
      const res = await fetch("/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, token })
      });
      const data = await res.json();
      document.getElementById("output").textContent = JSON.stringify(data, null, 2);
    };
  </script>
</body>
</html>
```

---

---

## ✅ Step 7: Run and Test

```bash
echo "OPENAI_API_KEY=your-openai-key" > .env
echo "JWT_SECRET=supersecretjwt" >> .env

npm install
node --loader ts-node/esm server.ts
```

Open: `http://localhost:3000/frontend/index.html`

---

## 🔐 Example Logins

| Username | Password | Role   |
|----------|----------|--------|
| alice    | pass123  | admin  |
| bob      | pass123  | viewer |

---

## 🧪 Example Queries

- "list all files"
- "check disk usage"

---
