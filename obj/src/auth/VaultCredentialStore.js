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
exports.VaultCredentialStore = void 0;
/** @module auth */
const pip_services3_commons_nodex_1 = require("pip-services3-commons-nodex");
const pip_services3_components_nodex_1 = require("pip-services3-components-nodex");
/**
 * Credential store that keeps credentials in memory.
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
 * @see [[ICredentialStore]]
 * @see [[CredentialParams]]
 *
 * ### Example ###
 *
 *
 *     let credentialStore = new VaultCredentialStore();
 *     credentialStore.open();
 *
 *     let credential = await credentialStore.lookup("123", "key1");
 *     // Result: user=jdoe; pass=pass123
 */
class VaultCredentialStore {
    /**
     * Creates a new instance of the credential store.
     *
     */
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
        this._root_path = config.getAsStringWithDefault('options.root_path', this._root_path);
        this._namespace = config.getAsStringWithDefault('options.namespace', this._namespace);
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
        return this._client;
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
            if (!status.sealed) {
                let err = new pip_services3_commons_nodex_1.ApplicationException("ERROR", correlationId, "OPEN_ERROR", "Vault server is sealed!");
                this._logger.error(correlationId, err, "Vault server is sealed!");
                this._client = null;
                throw err; // TODO: Decide, does need to throw error?
            }
            // open connection and get API token
            try {
                switch (this._auth_type) {
                    case "approle": {
                        this._token = yield this._client.loginWithAppRole(username, password).client_token;
                    }
                    case "ldap": {
                        this._token = yield this._client.loginWithLdap(username, password).client_token;
                    }
                    case "userpass": {
                        this._token = yield this._client.loginWithUserpass(username, password).client_token;
                    }
                    case "k8s": {
                        this._token = yield this._client.loginWithK8s(username, password).client_token;
                    }
                    case "cert": {
                        this._token = yield this._client.loginWithCert(username, password).client_token;
                    }
                    default: {
                        this._token = yield this._client.loginWithUserpass(username, password).client_token;
                    }
                }
            }
            catch (ex) {
                let err = new pip_services3_commons_nodex_1.ConnectionException(correlationId, "LOGIN_ERROR", "Can't login to Vault server").withCause(ex);
                this._logger.error(correlationId, ex, "Can't login to Vault server");
                this._client = null;
                throw err;
            }
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
        });
    }
    /**
     * Stores credential parameters into the store.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the credential parameters.
     * @param credential        a credential parameters to be stored.
     */
    store(correlationId, key, credential) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isOpen()) {
                try {
                    yield this._client.createKVSecret(this._token, key, credential);
                    this._logger.debug(correlationId, 'Stored key ' + key + ': ' + credential);
                    return;
                }
                catch (ex) {
                    this._logger.error(correlationId, ex, "Can't store KV to Vault with key: " + key);
                }
            }
        });
    }
    /**
     * Lookups credential parameters by its key.
     *
     * @param correlationId     (optional) transaction id to trace execution through call chain.
     * @param key               a key to uniquely identify the credential parameters.
     * @param callback          callback function that receives found credential parameters or error.
     */
    lookup(correlationId, key) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isOpen()) {
                try {
                    let data = yield this._client.readKVSecret(this._token, key);
                    this._logger.debug(correlationId, 'KVs for ' + key + ': ', data);
                    return data;
                }
                catch (ex) {
                    this._logger.error(correlationId, ex, "Can't lookup KV from Vault with key: " + key);
                }
            }
        });
    }
}
exports.VaultCredentialStore = VaultCredentialStore;
//# sourceMappingURL=VaultCredentialStore.js.map