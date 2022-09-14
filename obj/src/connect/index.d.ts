/**
 * @module connect
 *
 * [[VaultDiscovery]] – registry that is stored in HashiCorp Vault.
 *
 * There exist 2 types of discovery:
 * - Static discovery: all services have static IP addresses (like DNS, which also works using static
 * discovery) that are configured from the start and don't change along the way. As of lately, used
 * more often than dynamic, because it is simpler to use and more reliable.
 *     - Proxy (or reverse proxy) is created with a dns name, and all the dynamics of
 *     starting/restarting/switching from one host to another – everything is nice and clear
 *     for the clients. Infrastructure does all the hard work out of the box.
 *     - Configure sets the static registry.
 *
 * - Dynamic discovery: every time a service starts, it registers its address in the discovery
 * service ("Service name" at the following address "IP"). Clients then ask to resolve the address
 * by which the requested service can be reached. The service has a general name, by which other
 * services can resolve it.
 *     - If a service stops working, you need to refresh its address, clean stale addresses,
 *     heartbeats must be used – lots of problems and challenges.
 *
 * One service can have more than one address.
 */
export { VaultDiscovery } from './VaultDiscovery';
