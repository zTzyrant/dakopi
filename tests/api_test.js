/**
 * Dakopi API Test Suite
 *
 * Run with: bun run tests/api_test.js
 *
 * This script tests the main flows of the application:
 * 1. Authentication (Register, Login, Profile)
 * 2. Tags (Create, List)
 * 3. Articles (Create, Get, Update, List, Delete)
 * 4. Admin (Policies)
 * 5. Media (Upload placeholder)
 */

const BASE_URL = "http://localhost:3000/api";
let ACCESS_TOKEN = "";
let CURRENT_USER_ID = "";
let CREATED_ARTICLE_ID = "";
let CREATED_ARTICLE_SLUG = "";
let CREATED_TAG_ID = "";

// Utils
const colors = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
};

function log(msg, color = colors.reset) {
  console.log(`${color}${msg}${colors.reset}`);
}

async function request(method, endpoint, body = null, token = null) {
  const headers = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  log(`[${method}] ${endpoint}`, colors.cyan);

  try {
    const options = {
      method,
      headers,
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const res = await fetch(`${BASE_URL}${endpoint}`, options);
    const data = await res.json();

    return { status: res.status, data };
  } catch (error) {
    log(`❌ Connection Error: ${error.message}`, colors.red);
    return null;
  }
}

function assert(condition, message) {
  if (condition) {
    log(`   ✅ ${message}`, colors.green);
  } else {
    log(`   ❌ ${message}`, colors.red);
    // process.exit(1); // Optional: Stop on failure
  }
}

// --- Tests ---

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
  } else {
    // Might exist
    assert(res.data.code === "USER_EXISTS", "User registration (or already exists)");
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

  // 1. Create Tag
  const tagNames = ["Rust", "Programming", "System"];

  // We try to create one specific for this run
  const testTagName = `Tag-${Math.floor(Math.random() * 1000)}`;
  let res = await request("POST", "/articles/tags", { name: testTagName }, ACCESS_TOKEN);

  if (res.status === 200 || res.status === 201) {
    assert(true, "Tag created");
    CREATED_TAG_ID = res.data.data.id;
  } else if (res.status === 409) {
    log("   ℹ️ Tag already exists", colors.yellow);
  }

  // 2. List Tags
  res = await request("GET", "/articles/tags", null, ACCESS_TOKEN);
  assert(res.status === 200, "Tags listed");
  assert(Array.isArray(res.data.data), "Tags data is array");

  if (CREATED_TAG_ID) {
    const found = res.data.data.find((t) => t.id === CREATED_TAG_ID);
    assert(found, "Created tag found in list");
  }
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
    tags: CREATED_TAG_ID ? [CREATED_TAG_ID] : [],
  };

  let res = await request("POST", "/articles", payload, ACCESS_TOKEN);

  if (res.status === 200 || res.status === 201) {
    assert(true, "Article created");
    CREATED_ARTICLE_ID = res.data.data.id;
    CREATED_ARTICLE_SLUG = res.data.data.slug;

    // Validating Author Field
    assert(res.data.data.author, "Author field present");
    assert(res.data.data.author.username, "Author username present");
  } else {
    log(`Failed create article: ${JSON.stringify(res.data)}`, colors.red);
  }

  // 2. Get Article (ID)
  if (CREATED_ARTICLE_ID) {
    res = await request("GET", `/articles/${CREATED_ARTICLE_ID}`, null, ACCESS_TOKEN);
    assert(res.status === 200, "Get Article by ID success");
    assert(res.data.data.id === CREATED_ARTICLE_ID, "ID Matches");
  }

  // 3. Update Article
  if (CREATED_ARTICLE_ID) {
    const updatePayload = {
      title: "Updated Title",
      status: "published",
    };
    res = await request("PUT", `/articles/${CREATED_ARTICLE_ID}`, updatePayload, ACCESS_TOKEN);
    assert(res.status === 200, "Article updated");
    assert(res.data.data.title === "Updated Title", "Title updated");
    assert(res.data.data.status === "published", "Status updated");
  }

  // 4. List Articles
  res = await request("GET", "/articles?page=1&limit=5", null, ACCESS_TOKEN);
  assert(res.status === 200, "Articles listed");

  if (res.status === 200 && res.data.data && res.data.data.data) {
    assert(res.data.data.data.length > 0, "List is not empty");
    assert(res.data.data.data[0].author, "List items have author field");
  } else {
    log("   ⚠️ Skipping structure check due to list failure", colors.yellow);
  }

  // 5. Delete Article
  if (CREATED_ARTICLE_ID) {
    res = await request("DELETE", `/articles/${CREATED_ARTICLE_ID}`, null, ACCESS_TOKEN);
    assert(res.status === 200, "Article deleted");

    // Verify 404
    res = await request("GET", `/articles/${CREATED_ARTICLE_ID}`, null, ACCESS_TOKEN);
    assert(res.status === 404, "Article now 404");
  }
}

async function testAdmin() {
  log("\n--- Admin Tests ---", colors.blue);

  // Note: This requires the logged in user to be admin.
  // Usually the first registered user isn't default admin unless seeded.
  // We'll just try to hit the endpoint and expect either Forbidden or Success

  let res = await request("GET", "/admin/casbin/policies", null, ACCESS_TOKEN);
  if (res.status === 200) {
    assert(true, "Admin policies fetched (User is Admin)");
  } else if (res.status === 403) {
    log("   ℹ️ User is not admin (Expected for normal user)", colors.yellow);
  } else {
    log(`   ❓ Unexpected status: ${res.status}`, colors.red);
  }
}

async function main() {
  try {
    await testAuth();
    await testTags();
    await testArticles();
    await testAdmin();
    log("\n✨ All Tests Completed", colors.green);
  } catch (e) {
    console.error(e);
  }
}

main();
