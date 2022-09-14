/** @module connect */
import { ApplicationException, ConfigException, ConfigParams, ConnectionException, IConfigurable, IOpenable, IReferenceable, IReferences } from 'pip-services3-commons-nodex';
import { IReconfigurable } from 'pip-services3-commons-nodex';

import { CompositeLogger, ConnectionParams, ConnectionResolver, CredentialParams, CredentialResolver } from 'pip-services3-components-nodex';
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
 * 
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

export class VaultDiscovery implements IDiscovery, IReconfigurable, IReferenceable, IConfigurable, IOpenable {
    private _connectionResolver: ConnectionResolver = new ConnectionResolver();
    private _credentialResolver: CredentialResolver = new CredentialResolver();

    //connection params
    private _proxy_enable: boolean = false;
    private _proxy_port: number;
    private _proxy_host: string;

    // credentials
    private _auth_type: string = "userpass"
    private _file_cert: string;
    private _file_key: string;
    private _file_cacert: string;

    // options
    private _timeout: number = 5000;
    private _root_path: string;
    private _namespace: string;

    private _client: any = null;
    private _token: string;

    /** 
     * The logger.
     */
    protected _logger: CompositeLogger = new CompositeLogger();

    /**
     * Creates a new instance of discovery service.
     * 
     */
    public constructor() { }

    /**
    * Configures component by passing configuration parameters.
    * 
    * @param config    configuration parameters to be set.
    */
    public configure(config: ConfigParams): void {
        this._connectionResolver.configure(config);
        this._credentialResolver.configure(config);
        this._logger.configure(config);

        this._timeout = config.getAsIntegerWithDefault('options.timeout', this._timeout);
        this._root_path = config.getAsStringWithDefault('options.root_path', this._root_path);
        this._namespace = config.getAsStringWithDefault('options.namespace', this._namespace);
    }

    /**
    * Sets references to dependent components.
    * 
    * @param references 	references to locate the component dependencies. 
    */
    public setReferences(references: IReferences): void {
        this._connectionResolver.setReferences(references);
        this._credentialResolver.setReferences(references);
        this._logger.setReferences(references);
    }
    /**
     * Checks if the component is opened.
     * 
     * @returns true if the component has been opened and false otherwise.
    */
    public isOpen(): boolean {
        return this._client;
    }

    /**
     *  Helper method for resolve all additonal parameters
     */
    private resolveConfig(correlationId: string, connection: ConnectionParams, credential: CredentialParams) {

        // check configuration
        if (connection == null) {
            throw new ConfigException(
                correlationId,
                "NO_CONNECTION",
                "Connection is not configured"
            );
        }

        if (credential == null) {
            throw new ConfigException(
                correlationId,
                "NO_CREDENTIAL",
                "Credentials is not configured"
            );
        }

        // resolve additional credential params
        this._auth_type = credential.getAsStringWithDefault("auth_type", "userpass");
        this._file_cert = credential.getAsNullableString("file_cert");
        this._file_key = credential.getAsNullableString("file_key");
        this._file_cacert = credential.getAsNullableString("file_cacert");

        // resolve additionla connection params
        this._proxy_enable = connection.getAsBooleanWithDefault("proxy_enable", false);
        this._proxy_port = connection.getAsNullableInteger("proxy_port");
        this._proxy_host = connection.getAsNullableString("proxy_host");

    }

    /**
     *  Helper method for compose uri
     */
    private composeUri(correlationId: string, connection: ConnectionParams): string {

        if (connection.getUri() != null) {
            let uri = connection.getUri();
            if (uri) return uri;
        }

        let host = connection.getHost();
        if (host == null) {
            throw new ConfigException(
                correlationId,
                "NO_HOST",
                "Connection host is not set"
            );
        }

        let port = connection.getPort();
        if (port == 0) {
            throw new ConfigException(
                correlationId,
                "NO_PORT",
                "Connection port is not set"
            );
        }

        let protocol = connection.getProtocol();
        if (protocol == null) {
            throw new ConfigException(
                correlationId,
                "NO_PROTOCOL",
                "Connection protocol is not set"
            );
        }

        return protocol + '://' + host + ':' + port + '/v1';
    }

    /**
     * Opens the component.
     * 
     * @param correlationId 	(optional) transaction id to trace execution through call chain.
     */
    public async open(correlationId: string): Promise<void> {

        let connection = await this._connectionResolver.resolve(correlationId);
        let credential = await this._credentialResolver.lookup(correlationId);
        this.resolveConfig(correlationId, connection, credential);

        let options: any =
        {
            https: connection.getProtocol() === "https",
            baseUrl: this.composeUri(correlationId, connection),
            timeout: this._timeout,
            proxy: false,
        };

        // configure additional options
        if (this._root_path != null) {
            options.rootPath = this._root_path;
        }

        if (this._namespace != null) {
            options.namespace = this._namespace;
        }

        // configure https connection
        if (connection.getProtocol() === "https") {
            options.cert = this._file_cert;
            options.key = this._file_key;
            options.cacert = this._file_cacert;
        }

        // configure proxy
        if (this._proxy_enable) {
            options.proxy = {
                host: this._proxy_host,
                port: this._proxy_port
            }
        }

        // configure credentials
        let username: string;
        let password: string;

        if (credential != null) {
            username = credential.getUsername();
            password = credential.getPassword();
        }

        const Vault = require('hashi-vault-js');
        this._client = new Vault(options);
        const status = await this._client.healthCheck();
        // resolve status
        if (!status.sealed) {
            let err = new ApplicationException("ERROR", correlationId, "OPEN_ERROR", "Vault server is sealed!")
            this._logger.error(correlationId, err, "Vault server is sealed!")
            this._client = null;
            throw err // TODO: Decide, does need to throw error?
        }

        this._logger.debug(correlationId, "Vault status:", status)

        // open connection and get API token
        try {
            switch (this._auth_type) {
                case "approle": {
                    this._token = await this._client.loginWithAppRole(username, password).client_token;
                }
                case "ldap": {
                    this._token = await this._client.loginWithLdap(username, password).client_token;
                }
                case "userpass": {
                    this._token = await this._client.loginWithUserpass(username, password).client_token;
                }
                case "k8s": {
                    this._token = await this._client.loginWithK8s(username, password).client_token
                }
                case "cert": {
                    this._token = await this._client.loginWithCert(username, password).client_token;
                }
                default: {
                    this._token = await this._client.loginWithUserpass(username, password).client_token;
                }
            }
        } catch (ex) {
            let err = new ConnectionException(correlationId, "LOGIN_ERROR", "Can't login to Vault server").withCause(ex);
            this._logger.error(correlationId, ex, "Can't login to Vault server")
            this._client = null;
            throw err
        }
        this._logger.info(correlationId, "Vault Discovery Service opened with %s auth mode", this._auth_type);
        return
    }

    /**
    * Closes component and frees used resources.
    * 
    * @param correlationId 	(optional) transaction id to trace execution through call chain.
    */
    public async close(correlationId: string): Promise<void> {
        if (this.isOpen()) {
            this._client = null;
        }
        this._logger.info(correlationId, "Vault Discovery Service closed");
    }

    /**
     * Registers connection parameters into the discovery service.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connection parameters.
     * @param credential        a connection to be registered.
     * @returns 			    the registered connection parameters.
     */
    public async register(correlationId: string, key: string, connection: ConnectionParams): Promise<ConnectionParams> {
        if (this.isOpen()) {
            try {
                await this._client.createKVSecret(this._token, key, connection)
                this._logger.debug(correlationId, 'Register via key ' + key + ': ' + connection);
                return connection;
            } catch (ex) {
                this._logger.error(correlationId, ex, "Can't store KV to Vault with key: " + key);
            }

        }
    }

    /**
     * Resolves a single connection parameters by its key.
     * 
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connection.
     * @returns                 a found connection parameters or <code>null</code> otherwise
     */
    public async resolveOne(correlationId: string, key: string): Promise<ConnectionParams> {

        if (this.isOpen()) {
            try {
                let connection = await this._client.readKVSecret(this._token, key)
                this._logger.debug(correlationId, 'Resolved connection for ' + key + ': ', connection);
                return connection;
            } catch (ex) {
                this._logger.error(correlationId, ex, "Can't resolve KV from Vault with key: " + key);
            }

        }
    }

    /**
     * Resolves all connection parameters by their key.
     * 
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connections.
     * @returns                 all found connection parameters
     */
    public async resolveAll(correlationId: string, key: string): Promise<ConnectionParams[]> {
        
        if (this.isOpen()) {
            try {
                let data = await this._client.readKVSecret(this._token, key)
                this._logger.debug(correlationId, 'Resolved connections for ' + key + ': ', data);
                if (data as ConnectionParams[] != null) {
                    return data;
                }
                let connections: ConnectionParams[] = [];
                connections.push(data);
                return connections;
            } catch (ex) {
                this._logger.error(correlationId, ex, "Can't resolve KV from Vault with key: " + key);
            }
        }

    }
}