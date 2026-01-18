const client = require('../utils/client');
const { log, colors } = require('../utils/logger');

async function testAdmin() {
  log("\n--- Admin Tests ---", colors.blue);

  // Requires Admin Role
  let res = await client.request("GET", "/admin/casbin/policies");
  if (res.status === 200) {
    client.assert(true, "Admin policies fetched");
  } else if (res.status === 403) {
    log("   ℹ️ User is not admin (Expected)", colors.yellow);
  } else {
    log(`   ❌ Admin check failed unexpectedly: ${res.status}`, colors.red);
  }
}

module.exports = { testAdmin };
