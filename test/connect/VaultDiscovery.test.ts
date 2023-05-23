const assert = require('chai').assert;

import { ConfigParams } from 'pip-services3-commons-nodex';
import { ConnectionParams } from 'pip-services3-components-nodex';

import { VaultDiscovery } from '../../src/connect/VaultDiscovery';


suite('VaultDiscovery', ()=> {
    let discovery: VaultDiscovery

    let host = process.env['VAULT_HOST'] ?? 'localhost';
    let port = process.env['VAULT_PORT'] ?? '8201';
    
    let vaultConfig = ConfigParams.fromTuples(
        'connection.protocol', 'http',
        "connection.host", host,
        "connection.port", port,
        'credential.auth_type', 'userpass',
        'credential.username', 'user',
        'credential.password', 'pass',
    );  

    let connections = ConfigParams.fromTuples(
        "connKey1.host", "10.1.1.100",
        "connKey1.port", "8080",
        "connKey2.host", "10.1.1.101",
        "connKey2.port", "8082",
    );

    setup(async () => {
        discovery = new VaultDiscovery();
        discovery.configure(vaultConfig);
        await discovery.open(null);
        await discovery.loadVaultCredentials(connections);
    });

    test('Resolve connections', async () => {
        // Resolve one
        let connection = await discovery.resolveOne("123", "connKey1");

        assert.equal("10.1.1.100", connection.getHost());
        assert.equal(8080, connection.getPort());        

        connection = await discovery.resolveOne("123", "connKey2");

        assert.equal("10.1.1.101", connection.getHost());
        assert.equal(8082, connection.getPort());      

        // Resolve all
        await discovery.register(null, "connKey1",
            ConnectionParams.fromTuples("host", "10.3.3.151")
        );

        let connections = await discovery.resolveAll("123", "connKey1");
        
        assert.isTrue(connections.length > 1);

        await discovery.register(null, "connKey2",
            ConnectionParams.fromTuples("host", "15.7.7.1", "port", "8053")
        );

        connections = await discovery.resolveAll("123", "connKey2");

        assert.isTrue(connections.length > 1);

        await discovery.register(null, "connKey3",
            ConnectionParams.fromTuples("host", "7.7.0.0", "port", "8585")
        );

        connections = await discovery.resolveAll("123", "connKey3");

        assert.isTrue(connections.length == 1);

    });

});