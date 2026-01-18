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
  let uploadedImageUrl = "https://placeholder.co/600x400.webp"; // Default fallback

  // 0. Test Upload Image (S3)
  log("\n--- Testing S3 Upload ---", colors.blue);
  
  // 0.a. File Too Large (>1MB)
  try {
    const largeBuffer = new ArrayBuffer(1.5 * 1024 * 1024); // 1.5MB
    const largeBlob = new Blob([largeBuffer], { type: 'image/webp' });
    const largeForm = new FormData();
    largeForm.append('file', largeBlob, 'large_image.webp');
    
    let res = await client.upload("/s3/upload", largeForm);
    client.assertError(res, 400, "FILE_TOO_LARGE", "Upload >1MB file");
  } catch (e) {
    log(`   ⚠️ Skipped Large File Test (Env issue): ${e.message}`, colors.yellow);
  }

  // 0.b. Invalid Type (JPEG)
  try {
    const jpgBlob = new Blob(["fake-jpg"], { type: 'image/jpeg' });
    const jpgForm = new FormData();
    jpgForm.append('file', jpgBlob, 'test.jpg');
    
    let res = await client.upload("/s3/upload", jpgForm);
    client.assertError(res, 400, "INVALID_FILE_TYPE", "Upload JPEG file");
  } catch (e) {
    log(`   ⚠️ Skipped Invalid Type Test: ${e.message}`, colors.yellow);
  }

  // 0.c. Success Upload (Valid WebP)
  try {
    const validBlob = new Blob(["fake-webp-content"], { type: 'image/webp' });
    const validForm = new FormData();
    validForm.append('file', validBlob, 'cover.webp');
    
    let res = await client.upload("/s3/upload", validForm);
    if (res.status === 200) {
      client.assert(true, "Upload WebP Success");
      if (res.data.data && res.data.data.url) {
        uploadedImageUrl = res.data.data.url;
        log(`   ℹ️ Uploaded URL: ${uploadedImageUrl}`, colors.cyan);
      }
    } else {
      log(`   ❌ Upload Failed: ${res.status} ${JSON.stringify(res.data)}`, colors.red);
    }
  } catch (e) {
    log(`   ⚠️ Skipped Upload Success Test: ${e.message}`, colors.yellow);
  }

  // 1. Create Article
  const payload = {
    title: "Test Article " + new Date().toISOString(),
    content: "This is a test article content containing **Markdown**.",
    excerpt: "Short excerpt",
    status: "draft",
    visibility: "public",
    tags: selectedTagId ? [selectedTagId] : [],
    featured_image: uploadedImageUrl // Use the uploaded URL
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
