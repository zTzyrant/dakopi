const client = require('../utils/client');
const { log, colors } = require('../utils/logger');

async function testTags() {
  log("\n--- Tag Tests ---", colors.blue);
  
  let selectedTagId = "";

  // 1. List Tags (To pick one)
  let res = await client.request("GET", "/articles/tags");
  client.assert(res.status === 200, "Tags listed");

  if (res.status === 200 && Array.isArray(res.data.data) && res.data.data.length > 0) {
    const tags = res.data.data;
    const randomTag = tags[Math.floor(Math.random() * tags.length)];
    selectedTagId = randomTag.id;
    log(`   ℹ️ Selected Tag: ${randomTag.name} (${selectedTagId})`, colors.green);
  } else {
    log("   ⚠️ No tags found in list. Seeding might have failed or user can't see tags.", colors.yellow);
  }

  // 2. Create Tag (Try to create one)
  const testTagName = `Tag-${Math.floor(Math.random() * 1000)}`;
  res = await client.request("POST", "/articles/tags", { name: testTagName });

  if (res.status === 200 || res.status === 201) {
    client.assert(true, "Tag created (User allowed)");
    if (!selectedTagId) selectedTagId = res.data.data.id;
  } else if (res.status === 403) {
    log("   ℹ️ User cannot create tags (Expected for normal user if restricted)", colors.yellow);
  } else {
    log(`   ❌ Create Tag Failed: ${res.status}`, colors.red);
  }

  // 3. Negative: Create Empty Tag
  let badTag = await client.request("POST", "/articles/tags", { name: "" });
  client.assertError(badTag, 422, "VALIDATION_ERROR", "Create tag with empty name");

  return selectedTagId;
}

module.exports = { testTags };
