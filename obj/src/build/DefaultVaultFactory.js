"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultVaultFactory = void 0;
/** @module auth */
const pip_services3_commons_nodex_1 = require("pip-services3-commons-nodex");
const pip_services3_components_nodex_1 = require("pip-services3-components-nodex");
const VaultCredentialStore_1 = require("../auth/VaultCredentialStore");
const VaultDiscovery_1 = require("../connect/VaultDiscovery");
/**
 * Creates [[ICredentialStore]] components by their descriptors.
 *
 * @see [[IFactory]]
 * @see [[ICredentialStore]]
 * @see [[MemoryCredentialStore]]
 */
class DefaultVaultFactory extends pip_services3_components_nodex_1.Factory {
    /**
     * Create a new instance of the factory.
     */
    constructor() {
        super();
        this.registerAsType(DefaultVaultFactory.VaultCredentialStoreDescriptor, VaultCredentialStore_1.VaultCredentialStore);
        this.registerAsType(DefaultVaultFactory.VaultDiscoveryDescriptor, VaultDiscovery_1.VaultDiscovery);
    }
}
exports.DefaultVaultFactory = DefaultVaultFactory;
DefaultVaultFactory.VaultCredentialStoreDescriptor = new pip_services3_commons_nodex_1.Descriptor("pip-services", "credential-store", "hashicorp-vault", "*", "1.0");
DefaultVaultFactory.VaultDiscoveryDescriptor = new pip_services3_commons_nodex_1.Descriptor("pip-services", "discovery", "hashicorp-vault", "*", "1.0");
//# sourceMappingURL=DefaultVaultFactory.js.map