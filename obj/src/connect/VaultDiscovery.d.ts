/** @module connect */
import { ConfigParams, IConfigurable, IOpenable, IReferenceable, IReferences } from 'pip-services3-commons-nodex';
import { IReconfigurable } from 'pip-services3-commons-nodex';
import { CompositeLogger, ConnectionParams } from 'pip-services3-components-nodex';
import { IDiscovery } from 'pip-services3-components-nodex';
/**
 * Discovery service that keeps connections in memory.
 *
 * ### Configuration parameters ###
 *
 * - connection(s):
 *   - discovery_key:         (optional) a key to retrieve the connection from [[https://pip-services3-nodex.github.io/pip-services3-components-nodex/interfaces/connect.idiscovery.html IDiscovery]]
 *   - host:                  host name or IP address
 *   - port:                  port number
 *   - uri:                   resource URI or connection string with all parameters in it
 *   - proxy_enable:          enable proxy (default false)
 *   - proxy_host:            proxy host name
 *   - proxy_port:            proxy port number
 * - credential(s):
 *   - store_key:             key to retrieve parameters from credential store
 *   - username:              set user name for ldap and userpass auth type, role_id for approle and k8s auth type, cert_name for cert auth type
 *   - password:              user password for ldap and userpass auth type, secret_id for approle auth type, token for k8s and cert_name auth type
 *   - auth_type:             auth type (approle, ldap, userpass, k8s, cert) default - userpass
 *   - file_cert:             client certificate file for https mode
 *   - file_key:              client key file for https mode
 *   - file_cacert:           root CA cert path for https mode
 * - options:
 *   - root_path:             root path after the base URL
 *   - timeout:               default timeout in milliseconds (default: 5 sec)
 *   - namespace:             namespace (multi-tenancy) feature available on all Vault Enterprise versions
 * @see [[IDiscovery]]
 * @see [[ConnectionParams]]
 *
 *
 *     let discovery = new VaultDiscovery();
 *     discovery.open();
 *
 *     let connection = await discovery.resolve("123", "key1");
 *     // Result: host=10.1.1.100;port=8080
 *
 */
export declare class VaultDiscovery implements IDiscovery, IReconfigurable, IReferenceable, IConfigurable, IOpenable {
    private _connectionResolver;
    private _credentialResolver;
    private _proxy_enable;
    private _proxy_port;
    private _proxy_host;
    private _auth_type;
    private _file_cert;
    private _file_key;
    private _file_cacert;
    private _timeout;
    private _root_path;
    private _namespace;
    private _client;
    private _token;
    /**
     * The logger.
     */
    protected _logger: CompositeLogger;
    /**
    * Configures component by passing configuration parameters.
    *
    * @param config    configuration parameters to be set.
    */
    configure(config: ConfigParams): void;
    /**
    * Reads connections from configuration parameters.
    * And save it to Vault.
    *
    * @param config   configuration parameters to be read
    */
    loadVaultCredentials(config: ConfigParams): Promise<void>;
    /**
    * Sets references to dependent components.
    *
    * @param references 	references to locate the component dependencies.
    */
    setReferences(references: IReferences): void;
    /**
     * Checks if the component is opened.
     *
     * @returns true if the component has been opened and false otherwise.
    */
    isOpen(): boolean;
    /**
     *  Helper method for resolve all additonal parameters
     */
    private resolveConfig;
    /**
     *  Helper method for compose uri
     */
    private composeUri;
    /**
     * Opens the component.
     *
     * @param correlationId 	(optional) transaction id to trace execution through call chain.
     */
    open(correlationId: string): Promise<void>;
    /**
    * Closes component and frees used resources.
    *
    * @param correlationId 	(optional) transaction id to trace execution through call chain.
    */
    close(correlationId: string): Promise<void>;
    /**
     * Registers connection parameters into the discovery service.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connection parameters.
     * @param credential        a connection to be registered.
     * @returns 			    the registered connection parameters.
     */
    register(correlationId: string, key: string, connection: ConnectionParams): Promise<ConnectionParams>;
    /**
     * Resolves a single connection parameters by its key.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connection.
     * @returns                 a found connection parameters or <code>null</code> otherwise
     */
    resolveOne(correlationId: string, key: string): Promise<ConnectionParams>;
    /**
     * Resolves all connection parameters by their key.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connections.
     * @returns                 all found connection parameters
     */
    resolveAll(correlationId: string, key: string): Promise<ConnectionParams[]>;
}
