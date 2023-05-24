"use strict";
/** @module connect */
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
exports.VaultDiscovery = void 0;
const pip_services3_commons_nodex_1 = require("pip-services3-commons-nodex");
const pip_services3_components_nodex_1 = require("pip-services3-components-nodex");
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
class VaultDiscovery {
    constructor() {
        this._connectionResolver = new pip_services3_components_nodex_1.ConnectionResolver();
        this._credentialResolver = new pip_services3_components_nodex_1.CredentialResolver();
        //connection params
        this._proxy_enable = false;
        // credentials
        this._auth_type = "userpass";
        // options
        this._timeout = 5000;
        this._client = null;
        /**
         * The logger.
         */
        this._logger = new pip_services3_components_nodex_1.CompositeLogger();
    }
    /**
    * Configures component by passing configuration parameters.
    *
    * @param config    configuration parameters to be set.
    */
    configure(config) {
        this._connectionResolver.configure(config);
        this._credentialResolver.configure(config);
        this._logger.configure(config);
        this._timeout = config.getAsIntegerWithDefault('options.timeout', this._timeout);
        this._namespace = config.getAsStringWithDefault('options.namespace', this._namespace);
    }
    /**
    * Reads connections from configuration parameters.
    * And save it to Vault.
    *
    * @param config   configuration parameters to be read
    * @param rewrite   rewrite flag if key exists
    */
    loadVaultCredentials(config, rewrite) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            let items = new Map();
            if (config.length() > 0) {
                let connectionSections = config.getSectionNames();
                for (let index = 0; index < connectionSections.length; index++) {
                    let key = connectionSections[index];
                    let value = config.getSection(key);
                    let connectionsList = (_a = items.get(key)) !== null && _a !== void 0 ? _a : [];
                    connectionsList.push(new pip_services3_components_nodex_1.ConnectionParams(value));
                    items.set(key, connectionsList);
                }
            }
            // Register all connections in vault
            for (let key of items.keys()) {
                for (let conn of items.get(key)) {
                    if (!rewrite) {
                        try {
                            yield this._client.readKVSecret(this._token, key);
                        }
                        catch (ex) {
                            if (ex.response && ex.response.status == 404) {
                                yield this.register(null, key, conn);
                            }
                            else {
                                throw ex;
                            }
                        }
                    }
                    else {
                        yield this.register(null, key, conn);
                    }
                }
            }
        });
    }
    /**
    * Sets references to dependent components.
    *
    * @param references 	references to locate the component dependencies.
    */
    setReferences(references) {
        this._connectionResolver.setReferences(references);
        this._credentialResolver.setReferences(references);
        this._logger.setReferences(references);
    }
    /**
     * Checks if the component is opened.
     *
     * @returns true if the component has been opened and false otherwise.
    */
    isOpen() {
        return this._client != null;
    }
    /**
     *  Helper method for resolve all additonal parameters
     */
    resolveConfig(correlationId, connection, credential) {
        // check configuration
        if (connection == null) {
            throw new pip_services3_commons_nodex_1.ConfigException(correlationId, "NO_CONNECTION", "Connection is not configured");
        }
        if (credential == null) {
            throw new pip_services3_commons_nodex_1.ConfigException(correlationId, "NO_CREDENTIAL", "Credentials is not configured");
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
    composeUri(correlationId, connection) {
        if (connection.getUri() != null) {
            let uri = connection.getUri();
            if (uri)
                return uri;
        }
        let host = connection.getHost();
        if (host == null) {
            throw new pip_services3_commons_nodex_1.ConfigException(correlationId, "NO_HOST", "Connection host is not set");
        }
        let port = connection.getPort();
        if (port == 0) {
            throw new pip_services3_commons_nodex_1.ConfigException(correlationId, "NO_PORT", "Connection port is not set");
        }
        let protocol = connection.getProtocol();
        if (protocol == null) {
            throw new pip_services3_commons_nodex_1.ConfigException(correlationId, "NO_PROTOCOL", "Connection protocol is not set");
        }
        return protocol + '://' + host + ':' + port + '/v1';
    }
    /**
     * Opens the component.
     *
     * @param correlationId 	(optional) transaction id to trace execution through call chain.
     */
    open(correlationId) {
        return __awaiter(this, void 0, void 0, function* () {
            let connection = yield this._connectionResolver.resolve(correlationId);
            let credential = yield this._credentialResolver.lookup(correlationId);
            this.resolveConfig(correlationId, connection, credential);
            let options = {
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
                };
            }
            // configure credentials
            let username;
            let password;
            if (credential != null) {
                username = credential.getUsername();
                password = credential.getPassword();
            }
            const Vault = require('hashi-vault-js');
            this._client = new Vault(options);
            const status = yield this._client.healthCheck();
            // resolve status
            if (status.isVaultError || status.response) {
                let err = new pip_services3_commons_nodex_1.ApplicationException("ERROR", correlationId, "OPEN_ERROR", status.vaultHelpMessage);
                this._logger.error(correlationId, err, status.vaultHelpMessage, status.response);
                this._client = null;
                throw err;
            }
            else if (status.sealed) {
                let err = new pip_services3_commons_nodex_1.ApplicationException("ERROR", correlationId, "OPEN_ERROR", "Vault server is sealed!");
                this._logger.error(correlationId, err, "Vault server is sealed!");
                this._client = null;
                throw err; // TODO: Decide, does need to throw error?
            }
            this._logger.debug(correlationId, "Vault status:", status);
            // open connection and get API token
            try {
                switch (this._auth_type) {
                    case "approle": {
                        this._token = (yield this._client.loginWithAppRole(username, password)).client_token;
                        break;
                    }
                    case "ldap": {
                        this._token = (yield this._client.loginWithLdap(username, password)).client_token;
                        break;
                    }
                    case "userpass": {
                        this._token = (yield this._client.loginWithUserpass(username, password)).client_token;
                        break;
                    }
                    case "k8s": {
                        this._token = (yield this._client.loginWithK8s(username, password)).client_token;
                        break;
                    }
                    case "cert": {
                        this._token = (yield this._client.loginWithCert(username, password)).client_token;
                        break;
                    }
                    default: {
                        this._token = (yield this._client.loginWithUserpass(username, password)).client_token;
                        break;
                    }
                }
            }
            catch (ex) {
                let err = new pip_services3_commons_nodex_1.ConnectionException(correlationId, "LOGIN_ERROR", "Can't login to Vault server").withCause(ex);
                this._logger.error(correlationId, ex, "Can't login to Vault server");
                this._client = null;
                throw err;
            }
            this._logger.info(correlationId, "Vault Discovery Service opened with %s auth mode", this._auth_type);
            return;
        });
    }
    /**
    * Closes component and frees used resources.
    *
    * @param correlationId 	(optional) transaction id to trace execution through call chain.
    */
    close(correlationId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isOpen()) {
                this._client = null;
            }
            this._logger.info(correlationId, "Vault Discovery Service closed");
        });
    }
    /**
     * Registers connection parameters into the discovery service.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connection parameters.
     * @param credential        a connection to be registered.
     * @returns 			    the registered connection parameters.
     */
    register(correlationId, key, connection) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isOpen()) {
                try {
                    let connections = [];
                    let version = 0;
                    try {
                        let res = yield this._client.readKVSecret(this._token, key);
                        version = res.metadata.version;
                        // Check if connection already exists
                        if (res.data && res.data.connections) {
                            for (let conn of res.data.connections) {
                                if (connection.getHost() == conn.host && connection.getPort() == ((_a = conn.port) !== null && _a !== void 0 ? _a : 0)) {
                                    this._logger.info(correlationId, 'Connection already exists via key ' + key + ': ' + connection);
                                    return connection;
                                }
                            }
                            for (let conn of res.data.connections)
                                connections.push(new pip_services3_components_nodex_1.ConnectionParams(conn).getAsObject());
                        }
                    }
                    catch (ex) {
                        if (ex.response && ex.response.status == 404) {
                            // pass
                        }
                        else {
                            throw ex;
                        }
                    }
                    connections.push(connection.getAsObject());
                    if (version > 0) {
                        yield this._client.updateKVSecret(this._token, key, { connections: connections }, version);
                    }
                    else {
                        yield this._client.createKVSecret(this._token, key, { connections: connections });
                    }
                    this._logger.debug(correlationId, 'Register via key ' + key + ': ' + connection);
                    return connection;
                }
                catch (ex) {
                    this._logger.error(correlationId, ex, "Can't store KV to Vault with key: " + key);
                }
            }
        });
    }
    /**
     * Resolves a single connection parameters by its key.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connection.
     * @returns                 a found connection parameters or <code>null</code> otherwise
     */
    resolveOne(correlationId, key) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isOpen()) {
                try {
                    let res = yield this._client.readKVSecret(this._token, key);
                    this._logger.debug(correlationId, 'Resolved connection for ' + key + ': ', res);
                    let connection;
                    if (res.data && res.data.connections && res.data.connections.length > 0)
                        connection = new pip_services3_components_nodex_1.ConnectionParams(res.data.connections[0]);
                    return connection;
                }
                catch (ex) {
                    this._logger.error(correlationId, ex, "Can't resolve KV from Vault with key: " + key);
                }
            }
        });
    }
    /**
     * Resolves all connection parameters by their key.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the connections.
     * @returns                 all found connection parameters
     */
    resolveAll(correlationId, key) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isOpen()) {
                try {
                    let res = yield this._client.readKVSecret(this._token, key);
                    this._logger.debug(correlationId, 'Resolved connections for ' + key + ': ', res);
                    let connections = [];
                    for (let conn of res.data.connections)
                        connections.push(new pip_services3_components_nodex_1.ConnectionParams(conn));
                    return connections;
                }
                catch (ex) {
                    this._logger.error(correlationId, ex, "Can't resolve KV from Vault with key: " + key);
                }
            }
        });
    }
}
exports.VaultDiscovery = VaultDiscovery;
//# sourceMappingURL=VaultDiscovery.js.map