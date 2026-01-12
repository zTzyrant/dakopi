/**
 * Dakopi API Test Suite
 *
 * Run with: bun run tests/api_test.js
 *
 * This script tests the main flows of the application including NEGATIVE CASES.
 *
 * FEATURES:
 * - Logs all Request/Response details to a file (timestamped).
 * - Prompts user for Email Verification Token to test the flow.
 * - Validates Error Responses.
 */

const fs = require('fs');
const readline = require('readline');
const path = require('path');

const BASE_URL = "http://localhost:3000/api";

let ACCESS_TOKEN = "";
let CURRENT_USER_EMAIL = "";
let CURRENT_USER_ID = "";
let CREATED_ARTICLE_ID = "";
let SELECTED_TAG_ID = "";

// Logging Setup
const now = new Date();
const timestamp = now.toISOString().replace(/[:.]/g, '-');
const logFileName = `/logs/test_run_${timestamp}.tst.txt`;
const logPath = path.join(__dirname, logFileName);

// Utils
const colors = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

function writeLog(text) {
  fs.appendFileSync(logPath, text + '\n');
}

function log(msg, color = colors.reset) {
  console.log(`${color}${msg}${colors.reset}`);
  writeLog(msg.replace(/\x1b\[[0-9;]*m/g, '')); // Strip ANSI codes for file
}

function logDetail(header, content) {
  const divider = "-".repeat(50);
  const msg = `\n${divider}\n${header}\n${divider}\n${typeof content === 'object' ? JSON.stringify(content, null, 2) : content}\n`;
  writeLog(msg);
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function askQuestion(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

async function request(method, endpoint, body = null, token = null) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  log(`[${method}] ${endpoint}`, colors.cyan);

  // Log Request
  logDetail(`REQUEST: ${method} ${url}`, {
    headers,
    body
  });

  try {
    const options = {
      method,
      headers,
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const res = await fetch(url, options);

    let data;
    const contentType = res.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      data = await res.json();
    } else {
      data = await res.text();
    }

    // Log Response
    logDetail(`RESPONSE: ${res.status} ${res.statusText}`, data);

    return { status: res.status, data };
  } catch (error) {
    log(`❌ Connection Error: ${error.message}`, colors.red);
    logDetail("CONNECTION ERROR", error.message);
    return null;
  }
}

function assert(condition, message) {
  if (condition) {
    log(`   ✅ ${message}`, colors.green);
  } else {
    log(`   ❌ ${message}`, colors.red);
  }
}

function assertError(res, expectedStatus, expectedCode, message) {
  if (res.status === expectedStatus && res.data.code === expectedCode) {
    log(`   ✅ [Negative Case] ${message} - Caught ${expectedCode} (${expectedStatus})`, colors.green);
  } else {
    log(`   ❌ [Negative Case] ${message} - Failed. Got ${res.status} / ${res.data?.code}, Expected ${expectedStatus} / ${expectedCode}`, colors.red);
  }
}

// --- Negative Tests ---

async function testAuthNegative() {
  log("\n--- Authentication Negative Tests ---", colors.blue);

  // 1. Register - Bad Email
  let res = await request("POST", "/auth/register", {
    username: "baduser",
    email: "not-an-email",
    password: "password123"
  });
  // Validator error usually returns 422 or 400 with VALIDATION_ERROR
  assertError(res, 422, "VALIDATION_ERROR", "Register with invalid email format");

  // 2. Register - Password too short
  res = await request("POST", "/auth/register", {
    username: "shortpass",
    email: "short@example.com",
    password: "123"
  });
  assertError(res, 422, "VALIDATION_ERROR", "Register with short password");

  // 3. Login - Wrong Password
  // Assuming a user that doesn't exist returns AUTH_FAILED too, or we try random
  res = await request("POST", "/auth/login", {
    login_id: "nonexistentuser",
    password: "wrongpassword"
  });
  assertError(res, 401, "AUTH_FAILED", "Login with non-existent user");
}

async function testArticleNegative(token) {
  log("\n--- Article Negative Tests ---", colors.blue);

  // 1. Create Article - Validation (Title too short)
  let res = await request("POST", "/articles", {
    title: "No",
    content: "Valid content text here...",
    status: "draft",
    visibility: "public"
  }, token);
  assertError(res, 422, "VALIDATION_ERROR", "Create article with short title");

  // 2. Update Article - Not Found
  const randomUuid = "00000000-0000-0000-0000-000000000000";
  res = await request("PUT", `/articles/${randomUuid}`, { title: "Update" }, token);
  assertError(res, 404, "ARTICLE_NOT_FOUND", "Update non-existent article");

  // 3. Delete Article - Not Found
  res = await request("DELETE", `/articles/${randomUuid}`, null, token);
  assertError(res, 404, "ARTICLE_NOT_FOUND", "Delete non-existent article");
}

// --- Positive Tests ---

async function testAuth() {
  log("\n--- Authentication Tests ---", colors.blue);

  // 1. Register (Random User)
  const randomSuffix = Math.floor(Math.random() * 10000);
  const username = `testuser${randomSuffix}`;
  const email = `test${randomSuffix}@example.com`;
  const password = "password123";

  log(`Creating user: ${username} / ${email}`);

  let res = await request("POST", "/auth/register", { username, email, password });

  if (res.status === 201 || res.status === 200) {
    assert(true, "Registration successful");
    CURRENT_USER_EMAIL = email;
  } else {
    assert(false, `Registration failed: ${JSON.stringify(res.data)}`);
    return;
  }

  // 1.1 Register Duplicate (Negative Case integrated)
  log("   Testing Duplicate Register...");
  let dupRes = await request("POST", "/auth/register", { username, email, password });
  assertError(dupRes, 409, "AUTH_DUPLICATE", "Register duplicate user");


  // 1.5 Email Verification (Manual Step)
  log("\n⚠️  MANUAL ACTION REQUIRED ⚠️", colors.yellow);
  log(`An email has been sent to ${email} (check Mailpit/Console)`, colors.yellow);
  const token = await askQuestion(`${colors.yellow}Enter the Verification Token from the URL: ${colors.reset}`);

  if (token && token.trim() !== "") {
    // 1.5.1 Negative: Verify with bad token
    let badVer = await request("POST", "/auth/verify-email", { token: "invalid-token-string" });
    assertError(badVer, 400, "INVALID_TOKEN", "Verify with invalid token");

    // 1.5.2 Positive Verify
    res = await request("POST", "/auth/verify-email", { token: token.trim() });
    if (res.status === 200) {
      assert(true, "Email Verification successful");
    } else {
      log(`   ❌ Verification Failed: ${JSON.stringify(res.data)}`, colors.red);
    }
  } else {
    log("   ⏩ Skipping Email Verification (No token provided)", colors.yellow);
  }

  // 1.6 Resend Verification (Test Endpoint)
  log("Testing Resend Verification...");
  res = await request("POST", "/auth/verify-email/resend", { email });
  if (res.status === 200) {
    assert(true, "Resend verification request successful");
  } else if (res.status === 400 && res.data.code === "ALREADY_VERIFIED") {
    log("   ℹ️ Email already verified (Expected if previous step succeeded)", colors.green);
  } else {
    log(`   ❌ Resend Failed: ${JSON.stringify(res.data)}`, colors.red);
  }

  // 2. Login
  res = await request("POST", "/auth/login", { login_id: username, password });

  if (res.status === 200) {
    assert(true, "Login successful");
    ACCESS_TOKEN = res.data.data.token;
    assert(ACCESS_TOKEN.length > 0, "Token received");
  } else {
    log(`Login Failed: ${JSON.stringify(res.data)}`, colors.red);
    process.exit(1);
  }

  // 3. Profile
  res = await request("GET", "/auth/profile", null, ACCESS_TOKEN);
  if (res.status === 200) {
    assert(true, "Profile fetched");
    CURRENT_USER_ID = res.data.data.id;
    assert(res.data.data.username === username, "Username matches");
  }
}

async function testTags() {
  log("\n--- Tag Tests ---", colors.blue);

  // 1. List Tags (To pick one)
  let res = await request("GET", "/articles/tags", null, ACCESS_TOKEN);
  assert(res.status === 200, "Tags listed");

  if (res.status === 200 && Array.isArray(res.data.data) && res.data.data.length > 0) {
    const tags = res.data.data;
    const randomTag = tags[Math.floor(Math.random() * tags.length)];
    SELECTED_TAG_ID = randomTag.id;
    log(`   ℹ️ Selected Tag: ${randomTag.name} (${SELECTED_TAG_ID})`, colors.green);
  } else {
    log("   ⚠️ No tags found in list. Seeding might have failed or user can't see tags.", colors.yellow);
  }

  // 2. Create Tag (Try to create one)
  const testTagName = `Tag-${Math.floor(Math.random() * 1000)}`;
  res = await request("POST", "/articles/tags", { name: testTagName }, ACCESS_TOKEN);

  if (res.status === 200 || res.status === 201) {
    assert(true, "Tag created (User allowed)");
    if (!SELECTED_TAG_ID) SELECTED_TAG_ID = res.data.data.id;
  } else if (res.status === 403) {
    log("   ℹ️ User cannot create tags (Expected for normal user if restricted)", colors.yellow);
  } else {
    log(`   ❌ Create Tag Failed: ${res.status}`, colors.red);
  }

  // 3. Negative: Create Empty Tag
  let badTag = await request("POST", "/articles/tags", { name: "" }, ACCESS_TOKEN);
  assertError(badTag, 422, "VALIDATION_ERROR", "Create tag with empty name");
}

async function testArticles() {
  log("\n--- Article Tests ---", colors.blue);

  // 1. Create Article
  const payload = {
    title: "Test Article " + new Date().toISOString(),
    content: "This is a test article content containing **Markdown**.",
    excerpt: "Short excerpt",
    status: "draft",
    visibility: "public",
    tags: SELECTED_TAG_ID ? [SELECTED_TAG_ID] : [],
  };

  let res = await request("POST", "/articles", payload, ACCESS_TOKEN);

  if (res.status === 200 || res.status === 201) {
    assert(true, "Article created");
    CREATED_ARTICLE_ID = res.data.data.id;

    assert(res.data.data.author, "Author field present");
  } else {
    log(`Failed create article: ${JSON.stringify(res.data)}`, colors.red);
  }

  // 2. Get Article (ID)
  if (CREATED_ARTICLE_ID) {
    res = await request("GET", `/articles/${CREATED_ARTICLE_ID}`, null, ACCESS_TOKEN);
    assert(res.status === 200, "Get Article by ID success");
  }

  // 3. Update Article
  if (CREATED_ARTICLE_ID) {
    const updatePayload = {
      title: "Updated Title",
      status: "published",
    };
    res = await request("PUT", `/articles/${CREATED_ARTICLE_ID}`, updatePayload, ACCESS_TOKEN);
    assert(res.status === 200, "Article updated");
    if (res.status === 200) {
      assert(res.data.data.title === "Updated Title", "Title updated");
    }
  }

  // 4. List Articles
  res = await request("GET", "/articles?page=1&limit=5&status=published", null, ACCESS_TOKEN);
  assert(res.status === 200, "Articles listed (Published)");

  // 5. Delete Article
  if (CREATED_ARTICLE_ID) {
    res = await request("DELETE", `/articles/${CREATED_ARTICLE_ID}`, null, ACCESS_TOKEN);
    assert(res.status === 200, "Article deleted");

    // Verify 404 (Positive check for successful delete = 404 on get)
    res = await request("GET", `/articles/${CREATED_ARTICLE_ID}`, null, ACCESS_TOKEN);
    if (res.status === 404) {
      assert(true, "Article now 404 (Correctly deleted)");
    } else {
      log(`   ❌ Expected 404, got ${res.status}`, colors.red);
    }
  }
}

async function testAdmin() {
  log("\n--- Admin Tests ---", colors.blue);

  // Requires Admin Role
  let res = await request("GET", "/admin/casbin/policies", null, ACCESS_TOKEN);
  if (res.status === 200) {
    assert(true, "Admin policies fetched");
  } else if (res.status === 403) {
    log("   ℹ️ User is not admin (Expected)", colors.yellow);
  }
}

async function main() {
  log(`🚀 Starting Test Suite`, colors.magenta);
  log(`📝 Logs will be written to: ${logFileName}\n`);

  try {
    // Run Negative Auth Tests First
    await testAuthNegative();

    // Run Main Flow
    await testAuth();

    if (ACCESS_TOKEN) {
      // Run Article Negative Tests (Now that we have a token)
      await testArticleNegative(ACCESS_TOKEN);

      // Run Main Features
      await testTags();
      await testArticles();
      await testAdmin();
    } else {
      log("⚠️ Skipping remaining tests due to login failure", colors.red);
    }

    log("\n✨ All Tests Completed", colors.green);
  } catch (e) {
    console.error(e);
  } finally {
    rl.close();
  }
}

main();
