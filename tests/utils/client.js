const { log, logDetail, colors } = require('./logger');

const BASE_URL = "http://localhost:3000/api";

class ApiClient {
  constructor() {
    this.accessToken = "";
    this.refreshToken = "";
    this.currentUserEmail = "";
    this.currentUserId = "";
    
    // Stats
    this.stats = {
      passed: 0,
      failed: 0,
      skipped: 0
    };
  }

  setTokens(access, refresh) {
    this.accessToken = access;
    this.refreshToken = refresh;
  }

  setUser(id, email) {
    this.currentUserId = id;
    this.currentUserEmail = email;
  }

  async request(method, endpoint, body = null, token) {
    const url = `${BASE_URL}${endpoint}`;
    const headers = {
      "Content-Type": "application/json",
    };

    // Use provided token, or instance token, or none
    // If token is passed (even empty string), use it. If undefined, use this.accessToken.
    const authToken = token !== undefined ? token : this.accessToken;
    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }

    log(`[${method}] ${endpoint}`, colors.cyan);
    logDetail(`REQUEST: ${method} ${url}`, { headers, body });

    try {
      const options = { method, headers };
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

      logDetail(`RESPONSE: ${res.status} ${res.statusText}`, data);
      return { status: res.status, data };
    } catch (error) {
      log(`❌ Connection Error: ${error.message}`, colors.red);
      logDetail("CONNECTION ERROR", error.message);
      return { status: 0, data: null, error };
    }
  }

  async upload(endpoint, formData, token) {
    const url = `${BASE_URL}${endpoint}`;
    const headers = {}; // Let browser/fetch set Content-Type with boundary

    const authToken = token !== undefined ? token : this.accessToken;
    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }

    log(`[POST] UPLOAD ${endpoint}`, colors.cyan);
    // Note: Logging FormData content is tricky/verbose, skipping detail log for body

    try {
      const options = {
        method: "POST",
        headers,
        body: formData,
      };

      const res = await fetch(url, options);

      let data;
      const contentType = res.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        data = await res.json();
      } else {
        data = await res.text();
      }

      logDetail(`RESPONSE: ${res.status} ${res.statusText}`, data);
      return { status: res.status, data };
    } catch (error) {
      log(`❌ Connection Error: ${error.message}`, colors.red);
      return { status: 0, data: null, error };
    }
  }

  // Assertion Helpers
  assert(condition, message) {
    if (condition) {
      log(`   ✅ ${message}`, colors.green);
      this.stats.passed++;
    } else {
      log(`   ❌ ${message}`, colors.red);
      this.stats.failed++;
    }
    return condition;
  }

  assertError(res, expectedStatus, expectedCode, message) {
    if (res.status === expectedStatus && res.data?.code === expectedCode) {
      log(`   ✅ [Negative Case] ${message} - Caught ${expectedCode} (${expectedStatus})`, colors.green);
      this.stats.passed++;
      return true;
    } else {
      log(`   ❌ [Negative Case] ${message} - Failed. Got ${res.status} / ${res.data?.code}, Expected ${expectedStatus} / ${expectedCode}`, colors.red);
      this.stats.failed++;
      return false;
    }
  }

  skip(message) {
      log(`   ⏩ [SKIPPED] ${message}`, colors.yellow);
      this.stats.skipped++;
  }

  printSummary() {
      log("\n==========================================", colors.magenta);
      log("           TEST RUN SUMMARY              ", colors.magenta);
      log("==========================================", colors.magenta);
      log(`   ✅ PASSED:  ${this.stats.passed}`, colors.green);
      log(`   ❌ FAILED:  ${this.stats.failed}`, colors.red);
      log(`   ⏩ SKIPPED: ${this.stats.skipped}`, colors.yellow);
      log("==========================================\n", colors.magenta);
  }
}

module.exports = new ApiClient();
