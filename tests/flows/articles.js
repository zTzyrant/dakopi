const client = require('../utils/client');
const { log, colors } = require('../utils/logger');

async function testArticleNegative() {
  log("\n--- Article Negative Tests ---", colors.blue);

  // 1. Create Article - Validation (Title too short)
  let res = await client.request("POST", "/articles", {
    title: "No",
    content: "Valid content text here...",
    status: "draft",
    visibility: "public"
  });
  client.assertError(res, 422, "VALIDATION_ERROR", "Create article with short title");

  // 2. Update Article - Not Found
  const randomUuid = "00000000-0000-0000-0000-000000000000";
  res = await client.request("PUT", `/articles/${randomUuid}`, { title: "Update" });
  client.assertError(res, 404, "ARTICLE_NOT_FOUND", "Update non-existent article");

  // 3. Delete Article - Not Found
  res = await client.request("DELETE", `/articles/${randomUuid}`);
  client.assertError(res, 404, "ARTICLE_NOT_FOUND", "Delete non-existent article");
}

async function testArticles(selectedTagId) {
  log("\n--- Article Main Flow ---", colors.blue);
  
  let createdArticleId = "";

  // 1. Create Article
  const payload = {
    title: "Test Article " + new Date().toISOString(),
    content: "This is a test article content containing **Markdown**.",
    excerpt: "Short excerpt",
    status: "draft",
    visibility: "public",
    tags: selectedTagId ? [selectedTagId] : [],
  };

  let res = await client.request("POST", "/articles", payload);

  if (res.status === 200 || res.status === 201) {
    client.assert(true, "Article created");
    createdArticleId = res.data.data.id;
    client.assert(!!res.data.data.author, "Author field present");
  } else {
    log(`Failed create article: ${JSON.stringify(res.data)}`, colors.red);
  }

  // 2. Get Article (ID)
  if (createdArticleId) {
    res = await client.request("GET", `/articles/${createdArticleId}`);
    client.assert(res.status === 200, "Get Article by ID success");
  }

  // 3. Update Article
  if (createdArticleId) {
    const updatePayload = {
      title: "Updated Title",
      status: "published",
    };
    res = await client.request("PUT", `/articles/${createdArticleId}`, updatePayload);
    client.assert(res.status === 200, "Article updated");
    if (res.status === 200) {
      client.assert(res.data.data.title === "Updated Title", "Title updated");
    }
  }

  // 4. List Articles
  res = await client.request("GET", "/articles?page=1&limit=5&status=published");
  client.assert(res.status === 200, "Articles listed (Published)");

  // 5. Delete Article
  if (createdArticleId) {
    res = await client.request("DELETE", `/articles/${createdArticleId}`);
    client.assert(res.status === 200, "Article deleted");

    // Verify 404
    res = await client.request("GET", `/articles/${createdArticleId}`);
    if (res.status === 404) {
      client.assert(true, "Article now 404 (Correctly deleted)");
    } else {
      log(`   ❌ Expected 404, got ${res.status}`, colors.red);
    }
  }
}

module.exports = {
  testArticleNegative,
  testArticles
};
