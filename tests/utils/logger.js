const fs = require("fs");
const path = require("path");

const colors = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

// Logging Setup
const now = new Date();
const timestamp = now.toISOString().replace(/[:.]/g, "-");
const logsBaseDir = path.join(__dirname, "../../tests/logs");
const runDir = path.join(logsBaseDir, `run_${timestamp}`);

// Ensure run dir exists
if (!fs.existsSync(runDir)) {
  try {
    fs.mkdirSync(runDir, { recursive: true });
  } catch (e) {}
}

let currentModule = "general";

function setModule(moduleName) {
  currentModule = moduleName;
}

function getLogPath() {
  return path.join(runDir, `${currentModule}.md`);
}

function writeLog(text) {
  try {
    fs.appendFileSync(getLogPath(), text + "\n");
  } catch (e) {
    console.error("Failed to write to log file:", e);
  }
}

function log(msg, color = colors.reset) {
  // Print to console with color
  console.log(`${color}${msg}${colors.reset}`);

  // Clean ANSI for file
  const cleanMsg = msg.replace(/\x1b\[[0-9;]*m/g, "");

  // Markdown formatting tweaks
  let mdMsg = cleanMsg;
  if (cleanMsg.includes("---")) {
    mdMsg = `\n## ${cleanMsg.replace(/-+/g, "").trim()}\n`;
  } else if (cleanMsg.includes("✅")) {
    mdMsg = `- **SUCCESS**: ${cleanMsg.replace("✅", "").trim()}`;
  } else if (cleanMsg.includes("❌")) {
    mdMsg = `- **FAILED**: ${cleanMsg.replace("❌", "").trim()}`;
  } else if (cleanMsg.includes("⚠️")) {
    mdMsg = `> **WARNING**: ${cleanMsg.replace("⚠️", "").trim()}`;
  } else if (cleanMsg.includes("ℹ️")) {
    mdMsg = `> **INFO**: ${cleanMsg.replace("ℹ️", "").trim()}`;
  }

  writeLog(mdMsg);
}

function logDetail(header, content) {
  let md = `\n### ${header}\n`;

  if (content && typeof content === "object") {
    md += "```json\n" + JSON.stringify(content, null, 2) + "\n```\n";
  } else {
    md += "```text\n" + content + "\n```\n";
  }

  writeLog(md);
}

module.exports = {
  log,
  logDetail,
  colors,
  setModule,
  logFileName: runDir, // Exporting dir path instead of single file
};
