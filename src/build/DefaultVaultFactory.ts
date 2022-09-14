/** @module auth */
import { Descriptor } from 'pip-services3-commons-nodex';

import { Factory } from 'pip-services3-components-nodex';
import { VaultCredentialStore } from '../auth/VaultCredentialStore';
import { VaultDiscovery } from '../connect/VaultDiscovery';

/**
 * Creates [[ICredentialStore]] components by their descriptors.
 * 
 * @see [[IFactory]]
 * @see [[ICredentialStore]]
 * @see [[MemoryCredentialStore]]
 */
export class DefaultVaultFactory extends Factory {
	private static readonly VaultCredentialStoreDescriptor = new Descriptor("pip-services", "credential-store", "hashicorp-vault", "*", "1.0");
	private static readonly VaultDiscoveryDescriptor = new Descriptor("pip-services", "discovery", "hashicorp-vault", "*", "1.0");
	
	/**
	 * Create a new instance of the factory.
	 */
	public constructor() {
        super();
		this.registerAsType(DefaultVaultFactory.VaultCredentialStoreDescriptor, VaultCredentialStore);
		this.registerAsType(DefaultVaultFactory.VaultDiscoveryDescriptor, VaultDiscovery);
	}	
}
