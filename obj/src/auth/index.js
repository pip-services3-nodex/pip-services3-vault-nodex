"use strict";
/**
 * @module auth
 *
 * Todo: Rewrite this description
 *
 * @preferred
 * Contains credentials implementation.
 *
 * Credentials – passwords, logins, application keys, secrets. This information is usually linked
 * with connection parameters. Connection parameters separate from authentication, because auth.
 * is saved as a secret, and stored separately from configuration parameters (host name, ip
 * addresses). They need added security and protection, so they were separated.
 *
 * Credential parameters include various credentials.
 *
 * Interfaces and abstract classes for credential stores, which can save or retrieve various
 * credential parameters.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.VaultCredentialStore = void 0;
var VaultCredentialStore_1 = require("./VaultCredentialStore");
Object.defineProperty(exports, "VaultCredentialStore", { enumerable: true, get: function () { return VaultCredentialStore_1.VaultCredentialStore; } });
//# sourceMappingURL=index.js.map