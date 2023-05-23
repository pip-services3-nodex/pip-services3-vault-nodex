const assert = require('chai').assert;

import { ConfigParams } from 'pip-services3-commons-nodex';
import { CredentialParams } from 'pip-services3-components-nodex';

import { VaultCredentialStore } from '../../src/auth/VaultCredentialStore';


suite('VaultCredentialStore', ()=> {
    let credentialStore: VaultCredentialStore
    
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

    let credentials = ConfigParams.fromTuples(
        'credKey1.user', 'user1',
        'credKey1.pass', 'pass1',
        'credKey2.user', 'user2',
        'credKey2.pass', 'pass2',
    );

    setup(async () => {
        credentialStore = new VaultCredentialStore();
        credentialStore.configure(vaultConfig);
        await credentialStore.open(null);
        await credentialStore.loadVaultCredentials(credentials);
    });

    test('Lookup and store test', async () => {
        let cred1 = await credentialStore.lookup('123', 'credKey1');
        let cred2 = await credentialStore.lookup('123', 'credKey2');

        assert.equal(cred1.getUsername(), "user1");
        assert.equal(cred1.getPassword(), "pass1");
        assert.equal(cred2.getUsername(), "user2");
        assert.equal(cred2.getPassword(), "pass2");

        let credConfig = CredentialParams.fromTuples(
            'user', 'user3',
            'pass', 'pass3',
            'access_id', '123'
        );

        await credentialStore.store(null, 'credKey3', credConfig);

        let cred3 = await credentialStore.lookup('123', 'credKey3');

        assert.equal(cred3.getUsername(), "user3");
        assert.equal(cred3.getPassword(), "pass3");
        assert.equal(cred3.getAccessId(), "123");

        credConfig = CredentialParams.fromTuples(
            'user', 'new_user',
            'pass', 'new_pass',
            'access_id', 'new_id'
        );

        await credentialStore.store(null, 'credKey1', credConfig);

        cred1 = await credentialStore.lookup('123', 'credKey1');

        assert.equal(cred1.getUsername(), "new_user");
        assert.equal(cred1.getPassword(), "new_pass");
        assert.equal(cred1.getAccessId(), "new_id");
    });

});