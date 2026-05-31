const fs = require("fs");
const path = require("path");

/** Load .env.local or .env into plain object */
function loadEnvFile(filePath) {
  const env = {};
  if (!fs.existsSync(filePath)) return env;
  for (const line of fs.readFileSync(filePath, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1);
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    } else {
      value = value.trim();
    }
    env[key] = value;
  }
  return env;
}

const rootDir = __dirname;
const envPathLocal = path.join(rootDir, ".env.local");
const envPath = path.join(rootDir, ".env");
const fileEnv = { ...loadEnvFile(envPath), ...loadEnvFile(envPathLocal) };

module.exports = {
  apps: [
    {
      name: "sdap-api",
      cwd: rootDir,
      script: "api-server.js",
      interpreter: "node",
      env: {
        ...process.env,
        ...fileEnv,
        NODE_ENV: "production",
      },
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      max_restarts: 15,
      min_uptime: "8s",
      watch: false,
      merge_logs: true,
      time: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
    },
    {
      name: "sdap-web",
      cwd: rootDir,
      script: "web-server.js",
      interpreter: "node",
      env: {
        ...process.env,
        ...fileEnv,
        NODE_ENV: "production",
      },
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      max_restarts: 15,
      min_uptime: "8s",
      watch: false,
      merge_logs: true,
      time: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
    },
  ],
};
