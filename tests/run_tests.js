const readline = require("readline");
const { log, colors, logFileName, setModule } = require("./utils/logger");
const client = require("./utils/client");

// Flows
const authFlows = require("./flows/auth");
const articleFlows = require("./flows/articles");
const tagFlows = require("./flows/tags");
const adminFlows = require("./flows/admin");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

async function main() {
  log(`🚀 Starting Test Suite`, colors.magenta);
  log(`📝 Logs will be written to: ${logFileName}\n`);

  try {
    setModule("auth");
    // 1. Auth Negative
    await authFlows.testAuthNegative();

    // 2. Auth Positive (Register, Verify, Login)
    const authSuccess = await authFlows.testAuthPositive(rl);

    if (authSuccess) {
      // 3. OAuth Check (Just URL generation)
      await authFlows.testOAuth();

      // 4. Refresh Token Flow
      await authFlows.testRefreshToken();

      // 5. 2FA Flow
      // Note: This might change tokens/login session
      await authFlows.test2FA(rl);

      setModule("articles");
      // 6. Article Negative
      await articleFlows.testArticleNegative();

      setModule("tags");
      // 7. Tags (get ID)
      const selectedTagId = await tagFlows.testTags();

      setModule("articles");
      // 8. Articles (Main)
      await articleFlows.testArticles(selectedTagId);

      setModule("admin");
      // 9. Admin
      await adminFlows.testAdmin();

      setModule("auth");
      // 10. Logout
      await authFlows.testLogout();
    } else {
      log("⚠️ Skipping remaining tests due to login/auth failure", colors.red);
    }

    setModule("summary");
    log("\n✨ All Tests Completed", colors.green);
    client.printSummary();
  } catch (e) {
    console.error("Critical Error in Test Suite:", e);
  } finally {
    rl.close();
  }
}

main();
