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
- Docker (optional)
- OpenAI API key
- Basic Linux shell familiarity

---

## 📁 Folder Structure

```text
llm-secure-exec-demo/
├── auth.ts              # Login, JWT, audit logging, role policies
├── server.ts            # Express API routes
├── llm.ts               # OpenAI integration
├── executor.ts          # Shell command execution
├── frontend/index.html  # UI with login and command form
├── .env                 # Secrets (OpenAI key, JWT secret)
├── Dockerfile
├── docker-compose.yml
├── tsconfig.json
└── README.md
```

---

## 🧪 Step 1: Initialize the Project

```bash
mkdir llm-secure-exec-demo && cd llm-secure-exec-demo
npm init -y
npm install express openai dotenv jsonwebtoken
npm install --save-dev typescript ts-node
npx tsc --init
```

---

## 🔐 Step 2: Implement Authentication and Policy Engine

Create `auth.ts`:

```ts
import jwt from 'jsonwebtoken';
import { promises as fs } from 'fs';

const policyDB: Record<string, string[]> = {
  'admin': ['ls -la', 'df -h'],
  'viewer': ['ls -la'],
};

const auditLogPath = './audit.log';

export async function validateTokenAndPermissions(token: string, command: string) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as any;
    const role = decoded.role;
    const allowedCommands = policyDB[role] || [];

    const allowed = allowedCommands.includes(command);
    const entry = `[${new Date().toISOString()}] role=${role} command="${command}" allowed=${allowed}\n`;

    await fs.appendFile(auditLogPath, entry);

    if (!allowed) {
      return { valid: false, reason: 'Insufficient permissions' };
    }

    return { valid: true, reason: '' };
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
import { Configuration, OpenAIApi } from "openai";
import dotenv from "dotenv";

dotenv.config();

const configuration = new Configuration({ apiKey: process.env.OPENAI_API_KEY });
const openai = new OpenAIApi(configuration);

export async function getCommandFromLLM(query: string, token: string): Promise<string | null> {
  const prompt = `Translate this user query into a Linux command: "\${query}"`;
  const response = await openai.createCompletion({
    model: "text-davinci-003",
    prompt,
    max_tokens: 30,
    temperature: 0,
  });

  const command = response.data.choices[0]?.text?.trim();
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
import { getCommandFromLLM } from './llm';
import { validateTokenAndPermissions, login } from './auth';
import { executeCommand } from './executor';

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

Create `frontend/index.html`:

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
      admin: ["ls -la", "df -h"],
      viewer: ["ls -la"]
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

## 🐳 Step 7: Add Docker and Compose

Create `Dockerfile`:

```Dockerfile
FROM node:20
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["npm", "run", "start"]
```

Create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - OPENAI_API_KEY=your-openai-key-here
      - JWT_SECRET=supersecretjwt
```

---

## ✅ Step 8: Run and Test

```bash
echo "OPENAI_API_KEY=your-openai-key" > .env
echo "JWT_SECRET=supersecretjwt" >> .env

npm install
npx ts-node server.ts
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

## 📁 Upcoming Labs

- Lab 02: RBAC from external source (Redis/PostgreSQL)
- Lab 03: Preventing shell injection
- Lab 04: Streaming output and LLM responses
- Lab 05: Rate limiting and telemetry dashboard

---
