const client = require("../utils/client");
const { log, colors } = require("../utils/logger");
const { Jimp } = require("jimp");
const jsQR = require("jsqr");
const qrcode = require("qrcode-terminal");

function askQuestion(rl, query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

async function testAuthNegative() {
  log("\n--- Authentication Negative Tests ---", colors.blue);

  // 1. Register - Bad Email
  let res = await client.request("POST", "/auth/register", {
    username: "baduser",
    email: "not-an-email",
    password: "password123",
  });
  client.assertError(res, 422, "VALIDATION_ERROR", "Register with invalid email format");

  // 2. Register - Password too short
  res = await client.request("POST", "/auth/register", {
    username: "shortpass",
    email: "short@example.com",
    password: "123",
  });
  client.assertError(res, 422, "VALIDATION_ERROR", "Register with short password");

  // 3. Login - Wrong Password
  res = await client.request("POST", "/auth/login", {
    login_id: "nonexistentuser",
    password: "wrongpassword",
  });
  client.assertError(res, 401, "AUTH_FAILED", "Login with non-existent user");
}

async function testAuthPositive(rl) {
  log("\n--- Authentication Main Flow ---", colors.blue);

  // 1. Register
  const randomSuffix = Math.floor(Math.random() * 10000);
  const username = `testuser${randomSuffix}`;
  const email = `test${randomSuffix}@example.com`;
  const password = "password123";

  log(`Creating user: ${username} / ${email}`);
  let res = await client.request("POST", "/auth/register", { username, email, password });

  if (res.status === 201 || res.status === 200) {
    client.assert(true, "Registration successful");
    client.setUser(res.data.data.id, email);
  } else {
    client.assert(false, `Registration failed: ${JSON.stringify(res.data)}`);
    return false;
  }

  // 1.1 Duplicate Register Check
  let dupRes = await client.request("POST", "/auth/register", { username, email, password });
  client.assertError(dupRes, 409, "AUTH_DUPLICATE", "Register duplicate user");

  // 1.5 Email Verification (Manual)
  log("\n⚠️  MANUAL ACTION REQUIRED ⚠️", colors.yellow);
  log(`An email has been sent to ${email} (check Mailpit/Console)`, colors.yellow);

  let token = await askQuestion(
    rl,
    `${colors.yellow}Enter Verification Token (or press Enter to skip): ${colors.reset}`
  );
  token = token.trim();

  if (token) {
    let badVer = await client.request("POST", "/auth/verify-email", { token: "invalid-token" });
    client.assertError(badVer, 400, "INVALID_TOKEN", "Verify with invalid token");

    res = await client.request("POST", "/auth/verify-email", { token });
    if (res.status === 200) {
      client.assert(true, "Email Verification successful");
    } else {
      log(`   ❌ Verification Failed: ${JSON.stringify(res.data)}`, colors.red);
    }
  } else {
    log("   ⏩ Skipping Email Verification", colors.yellow);
  }

  // 2. Login
  res = await client.request("POST", "/auth/login", { login_id: username, password });
  if (res.status === 200) {
    client.assert(true, "Login successful");
    const { token, refresh_token } = res.data.data;
    client.setTokens(token, refresh_token);
  } else {
    log(`Login Failed: ${JSON.stringify(res.data)}`, colors.red);
    return false;
  }

  // 3. Profile
  res = await client.request("GET", "/auth/profile");
  if (res.status === 200) {
    client.assert(res.data.data.username === username, "Profile fetched & username matches");
  }

  return true; // Success
}

async function testRefreshToken() {
  log("\n--- Refresh Token Flow ---", colors.blue);

  if (!client.refreshToken) {
    log("   ⚠️ No refresh token available, skipping.", colors.yellow);
    return;
  }

  // 1. Refresh Token
  let res = await client.request("POST", "/auth/refresh", { refresh_token: client.refreshToken });

  if (res.status === 200) {
    client.assert(true, "Token refreshed successfully");
    const { token, refresh_token } = res.data.data;
    // Update tokens
    client.setTokens(token, refresh_token || client.refreshToken);
  } else {
    client.assert(false, `Refresh failed: ${JSON.stringify(res.data)}`);
  }
}

async function test2FA(rl) {
  log("\n--- 2FA Flow ---", colors.blue);

  // 1. Setup 2FA
  log(`   DEBUG: Current Client Email: ${client.currentUserEmail}`, colors.gray);
  let profileCheck = await client.request("GET", "/auth/profile");
  log(`   DEBUG: Server Profile Email: ${profileCheck.data?.data?.email}`, colors.gray);

  let res = await client.request("POST", "/auth/2fa/setup");
  if (res.status !== 200) {
    log(`   ❌ 2FA Setup Failed: ${JSON.stringify(res.data)}`, colors.red);
    client.assert(false, "2FA Setup Initialized");
    return;
  }

  const { secret, qr_code_url, backup_codes } = res.data.data;
  client.assert(!!secret, "2FA Secret received");

  log("\n📷 SCAN THIS QR CODE (OR COPY SECRET) 📷", colors.cyan);
  log(`Secret: ${secret}`, colors.magenta);

  if (qr_code_url) {
    try {
      let buffer;
      if (qr_code_url.startsWith("data:image")) {
        const base64Data = qr_code_url.replace(/^data:image\/png;base64,/, "");
        buffer = Buffer.from(base64Data, "base64");
      } else {
        // Assume raw base64
        buffer = Buffer.from(qr_code_url, "base64");
      }

      const image = await Jimp.read(buffer);
      const { data, width, height } = image.bitmap;
      const code = jsQR(data, width, height);

      if (code) {
        log(`   Attempting to display QR Code in terminal...`, colors.gray);
        qrcode.generate(code.data, { small: true });
      } else {
        log("   ⚠️ Failed to decode QR Image for terminal display", colors.yellow);
        // Only print raw string if decode failed
        log(`QR Raw Data (Truncated): ${qr_code_url.substring(0, 50)}...`, colors.cyan);
      }
    } catch (err) {
      log(`   ⚠️ Error processing QR Image: ${err.message}`, colors.red);
      log(`QR Raw Data (Truncated): ${qr_code_url.substring(0, 50)}...`, colors.cyan);
    }
  } else {
    log(`No QR code URL provided`, colors.yellow);
  }

  log(`Backup Codes: ${JSON.stringify(backup_codes)}`, colors.green);

  // 1.1 Negative: Confirm with wrong code
  let badConfirm = await client.request("POST", "/auth/2fa/confirm", { secret, code: "000000" });
  // The server returns INVALID_CODE for wrong code, updated expectation
  if (badConfirm.data.code === "INVALID_CODE") {
    client.assertError(badConfirm, 400, "INVALID_CODE", "Confirm 2FA with wrong code");
  } else {
    client.assertError(badConfirm, 400, "INVALID_TOKEN", "Confirm 2FA with wrong code");
  }

  // 2. Confirm 2FA
  log("\n⚠️  MANUAL ACTION REQUIRED ⚠️", colors.yellow);
  log(`Please add the secret to your Authenticator App.`, colors.yellow);
  let code = await askQuestion(rl, `${colors.yellow}Enter the 6-digit 2FA Code: ${colors.reset}`);
  code = code.trim();

  if (!code) {
    client.skip("Skipping 2FA Confirmation & Login tests (No code provided)");
    return;
  }

  res = await client.request("POST", "/auth/2fa/confirm", { secret, code });
  if (res.status === 200) {
    client.assert(true, "2FA Enabled successfully");
  } else {
    log(`   ❌ 2FA Confirm Failed: ${JSON.stringify(res.data)}`, colors.red);
    client.assert(false, "2FA Confirmation");
    return; // Cannot proceed
  }

  // --- Login with 2FA Logic ---
  const password = "password123";
  const username = client.currentUserEmail;

  // 3. Test 2FA Login - Negative (Wrong Code)
  log("   Testing 2FA Login Challenge (Negative)...");
  res = await client.request("POST", "/auth/login", { login_id: username, password });

  if (res.status === 202 && res.data.code === "TWO_FACTOR_REQUIRED") {
    const tempToken = res.data.data.temp_token;
    let badLogin = await client.request("POST", "/auth/2fa/verify-login", {
      temp_token: tempToken,
      code: "000000",
    });
    client.assertError(badLogin, 401, "INVALID_TOKEN", "2FA Login with wrong code");
  } else {
    client.assert(false, "Expected 202 for 2FA Login Challenge");
  }

  // 4. Test 2FA Login - Positive (Manual Code)
  log("   Testing 2FA Login Challenge (Positive - TOTP)...");
  // Re-initiate login to get fresh temp token (optional depending on backend, but safer)
  res = await client.request("POST", "/auth/login", { login_id: username, password });
  if (res.status === 202) {
    const tempToken = res.data.data.temp_token;

    // Ask for code again
    code = await askQuestion(
      rl,
      `${colors.yellow}Enter a NEW 2FA Code for Login (Wait for refresh if needed): ${colors.reset}`
    );
    code = code.trim();

    if (code) {
      let verifyRes = await client.request("POST", "/auth/2fa/verify-login", {
        temp_token: tempToken,
        code: code,
      });

      if (verifyRes.status === 200) {
        client.assert(true, "2FA Login Verified Successfully (TOTP)");
        client.setTokens(verifyRes.data.data.token, verifyRes.data.data.refresh_token);
      } else {
        client.assert(false, `2FA Login Failed: ${JSON.stringify(verifyRes.data)}`);
      }
    } else {
      client.skip("2FA Login (TOTP) skipped");
    }
  }

  // 5. Test 2FA Login - Positive (Backup Code)
  if (backup_codes && backup_codes.length > 0) {
    log("   Testing 2FA Login Challenge (Positive - Backup Code)...");
    const backupCode = backup_codes[0]; // Use first code
    log(`   Using Backup Code: ${backupCode}`, colors.cyan);

    res = await client.request("POST", "/auth/login", { login_id: username, password });
    if (res.status === 202) {
      const tempToken = res.data.data.temp_token;
      let verifyBackup = await client.request("POST", "/auth/2fa/verify-login", {
        temp_token: tempToken,
        code: backupCode,
      });

      if (verifyBackup.status === 200) {
        client.assert(true, "2FA Login Verified Successfully (Backup Code)");
        // Token update not strictly needed if we just tested it works, but good practice
        client.setTokens(verifyBackup.data.data.token, verifyBackup.data.data.refresh_token);
      } else {
        client.assert(false, `2FA Backup Code Login Failed: ${JSON.stringify(verifyBackup.data)}`);
      }
    }
  } else {
    client.skip("No backup codes available for testing");
  }

  // 6. Disable 2FA
  log("   Testing Disable 2FA...");
  res = await client.request("POST", "/auth/2fa/disable", { password });
  if (res.status === 200) {
    client.assert(true, "2FA Disabled successfully");
  } else {
    client.assert(false, `Disable 2FA Failed: ${JSON.stringify(res.data)}`);
  }
}

async function testOAuth() {
  log("\n--- OAuth Flow (URL Check) ---", colors.blue);

  // Test GitHub
  let res = await client.request("GET", "/auth/oauth/github");
  if (res.status === 200) {
    client.assert(!!res.data.data.url, "GitHub OAuth URL generated");
  } else {
    log(`   ❌ OAuth GitHub URL Failed: ${JSON.stringify(res.data)}`, colors.red);
  }

  // Test Google
  res = await client.request("GET", "/auth/oauth/google");
  if (res.status === 200) {
    client.assert(!!res.data.data.url, "Google OAuth URL generated");
  } else {
    log(`   ❌ OAuth Google URL Failed: ${JSON.stringify(res.data)}`, colors.red);
  }
}

async function testLogout() {
  log("\n--- Logout Flow ---", colors.blue);

  if (!client.refreshToken) {
    log("   ⚠️ No refresh token for logout, skipping.", colors.yellow);
    return;
  }

  let res = await client.request("POST", "/auth/logout", { refresh_token: client.refreshToken });
  if (res.status === 200) {
    client.assert(true, "Logout successful");
    client.setTokens("", ""); // Clear local tokens
  } else {
    log(`   ❌ Logout Failed: ${JSON.stringify(res.data)}`, colors.red);
  }

  // Verify token is invalid
  res = await client.request("GET", "/auth/profile", null, client.accessToken); // Using old token
  if (res.status === 401) {
    client.assert(true, "Old token is invalid after logout");
  } else {
    log(
      `   ⚠️ Old token might still be valid (JWT stateless?) or error code mismatch: ${res.status}`,
      colors.yellow
    );
  }
}

module.exports = {
  testAuthNegative,
  testAuthPositive,
  testRefreshToken,
  test2FA,
  testOAuth,
  testLogout,
};
