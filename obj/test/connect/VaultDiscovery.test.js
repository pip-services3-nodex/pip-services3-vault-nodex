"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('chai').assert;
const pip_services3_commons_nodex_1 = require("pip-services3-commons-nodex");
const pip_services3_components_nodex_1 = require("pip-services3-components-nodex");
const VaultDiscovery_1 = require("../../src/connect/VaultDiscovery");
suite('VaultDiscovery', () => {
    var _a, _b;
    let discovery;
    let host = (_a = process.env['VAULT_HOST']) !== null && _a !== void 0 ? _a : 'localhost';
    let port = (_b = process.env['VAULT_PORT']) !== null && _b !== void 0 ? _b : '8201';
    let vaultConfig = pip_services3_commons_nodex_1.ConfigParams.fromTuples('connection.protocol', 'http', "connection.host", host, "connection.port", port, 'credential.auth_type', 'userpass', 'credential.username', 'user', 'credential.password', 'pass');
    let connections = pip_services3_commons_nodex_1.ConfigParams.fromTuples("connKey1.host", "10.1.1.100", "connKey1.port", "8080", "connKey2.host", "10.1.1.101", "connKey2.port", "8082");
    setup(() => __awaiter(void 0, void 0, void 0, function* () {
        discovery = new VaultDiscovery_1.VaultDiscovery();
        discovery.configure(vaultConfig);
        yield discovery.open(null);
        yield discovery.loadVaultCredentials(connections);
    }));
    test('Resolve connections', () => __awaiter(void 0, void 0, void 0, function* () {
        // Resolve one
        let connection = yield discovery.resolveOne("123", "connKey1");
        assert.equal("10.1.1.100", connection.getHost());
        assert.equal(8080, connection.getPort());
        connection = yield discovery.resolveOne("123", "connKey2");
        assert.equal("10.1.1.101", connection.getHost());
        assert.equal(8082, connection.getPort());
        // Resolve all
        yield discovery.register(null, "connKey1", pip_services3_components_nodex_1.ConnectionParams.fromTuples("host", "10.3.3.151"));
        let connections = yield discovery.resolveAll("123", "connKey1");
        assert.isTrue(connections.length > 1);
        yield discovery.register(null, "connKey2", pip_services3_components_nodex_1.ConnectionParams.fromTuples("host", "15.7.7.1", "port", "8053"));
        connections = yield discovery.resolveAll("123", "connKey2");
        assert.isTrue(connections.length > 1);
        yield discovery.register(null, "connKey3", pip_services3_components_nodex_1.ConnectionParams.fromTuples("host", "7.7.0.0", "port", "8585"));
        connections = yield discovery.resolveAll("123", "connKey3");
        assert.isTrue(connections.length == 1);
    }));
});
//# sourceMappingURL=VaultDiscovery.test.js.map