import { Factory } from 'pip-services3-components-nodex';
/**
 * Creates [[ICredentialStore]] components by their descriptors.
 *
 * @see [[IFactory]]
 * @see [[ICredentialStore]]
 * @see [[MemoryCredentialStore]]
 */
export declare class DefaultVaultFactory extends Factory {
    private static readonly VaultCredentialStoreDescriptor;
    private static readonly VaultDiscoveryDescriptor;
    /**
     * Create a new instance of the factory.
     */
    constructor();
}
