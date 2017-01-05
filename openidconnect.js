/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The following software is included for convenience: JSJWS, JSRSASIGN, CryptoJS;
 * Use of any of these software may be governed by their respective licenses.
 */

/**
  * The 'jsjws'(JSON Web Signature JavaScript Library) License
  *
  * Copyright (c) 2012 Kenji Urushima
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in
  * all copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  * THE SOFTWARE.
 */

/**
 * The 'jsrsasign'(RSA-Sign JavaScript Library) License
 *
 * Copyright (c) 2010-2013 Kenji Urushima
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

/**
 * The Crypto-JS  license
 *
 * (c) 2009-2013 by Jeff Mott. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list
 * of conditions, and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions, and the following disclaimer in the documentation or other
 * materials provided with the distribution.
 *
 * Neither the name CryptoJS nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS," AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */



/**
 * OIDC namespace
 * @namespace OIDC
 */
var OIDC = namespace('OIDC');

/**
 * @property {array} OIDC.supportedProviderOptions                                 - List of the Identity Provider's configuration parameters
 * @property {string} OIDC.supportedProviderOptions.issuer                         - Issuer ID
 * @property {string} OIDC.supportedProviderOptions.authorization_endpoint         - Authorization Endpoint URL
 * @property {string} OIDC.supportedProviderOptions.jwks_uri                       - JWKS URL
 * @property {boolean} OIDC.supportedProviderOptions.claims_parameter_supported    - Claims parameter support
 * @property {boolean} OIDC.supportedProviderOptions.request_parameter_supported   - Request parameter support
 * @property {object} OIDC.supportedProviderOptions.jwks                           - Identity Provider's JWK Set
 * @readonly
 * @memberof OIDC
 */
OIDC.supportedProviderOptions = [
    'issuer',
    'authorization_endpoint',
    'jwks_uri',
    'claims_parameter_supported',
    'request_parameter_supported',
    'jwks'

    /*
    / Reserve for future use
    'token_endpoint',
    'userinfo_endpoint',
    'check_session_iframe',
    'end_session_endpoint',
    'registration_endpoint',
    'scopes_supported',
    'response_types_supported',
    'grant_types_supported',
    'acr_values_supported',
    'subject_types_supported',
    'userinfo_signing_alg_values_supported',
    'userinfo_encryption_alg_values_supported',
    'id_token_signing_alg_values_supported',
    'id_token_encryption_alg_values_supported',
    'id_token_encryption_enc_values_supported',
    'request_object_signing_alg_values_supported',
    'request_object_encryption_alg_values_supported',
    'request_object_encryption_enc_values_supported',
    'token_endpoint_auth_methods_supported',
    'token_endpoint_auth_signing_alg_values_supported',
    'display_values_supported',
    'claim_types_supported',
    'claims_supported',
    'service_documentation',
    'ui_locales_supported',
    'require_request_uri_registration',
    'op_policy_uri',
    'op_tos_uri',
    'claims_locales_supported',
    'request_uri_parameter_supported',
    */
];

/**
 * @property {array} OIDC.supportedRequestOptions             - Supported Login Request parameters
 * @property {string} OIDC.supportedRequestOptions.scope      - space separated scope values
 * @property {string} OIDC.supportedRequestOptions.response_type  - space separated response_type values
 * @property {string} OIDC.supportedRequestOptions.display    - display
 * @property {string} OIDC.supportedRequestOptions.max_age    - max_age
 * @property {object} OIDC.supportedRequestOptions.claims    - claims object containing what information to return in the UserInfo endpoint and ID Token
 * @property {array} OIDC.supportedRequestOptions.claims.id_token    - list of claims to return in the ID Token
 * @property {array} OIDC.supportedRequestOptions.claims.userinfo    - list of claims to return in the UserInfo endpoint
 * @property {boolean} OIDC.supportedRequestOptions.request   - signed request object JWS. Not supported yet.
 * @readonly
 * @memberof OIDC
 *
 */
OIDC.supportedRequestOptions = [
    'scope',
    'response_type',
    'display',
    'max_age',
    'claims',
    'request'
];

/**
 * @property {array} OIDC.supportedClientOptions                 - List of supported Client configuration parameters
 * @property {string} OIDC.supportedClientOptions.client_id      - The client's client_id
 * @property {string} OIDC.supportedClientOptions.redirect_uri   - The client's redirect_uri
 * @readonly
 * @memberof OIDC
 *
 */
OIDC.supportedClientOptions = [
    'client_id',
    'redirect_uri'
//    'client_secret',
];


/**
 * Sets the Identity Provider's configuration parameters
 * @function setProviderInfo
 * @memberof OIDC
 * @param {object} p      - The Identity Provider's configuration options described in {@link OIDC.supportedProviderOptions}
 * @returns {boolean}     - Indicates status of
 * @example
 * // set Identity Provider configuration
 * OIDC.setProviderInfo( {
 *                          issuer: 'https:/op.example.com',
 *                          authorization_endpoint: 'http://op.example.com/auth.html',
 *                          jwks_uri: 'https://op.example.com/jwks'
 *                       }
 *                     );
 *
 * // set Identity Provider configuration using discovery information
 * var discovery = OIDC.discover('https://op.example.com');
 * if(var)
 *     OIDC.setProviderInfo(discovery);
 */
OIDC.setProviderInfo = function (p) {
    var params = this.supportedProviderOptions;

    if (p !== 'undefined') {
        for (var i = 0; i < params.length; i++) {
            if (p[params[i]] !== 'undefined') {
                this[params[i]] = p[params[i]];
            }
        }
    }
    return true;
};


/**
 * Sets the Client's configuration parameters
 * @function setClientInfo
 * @memberof OIDC
 * @param {object} p      - The Client's configuration options described in {@link OIDC.supportedClientOptions}
 * @returns {boolean}       Indicates status of call
 * @example
 * // set client_id and redirect_uri
 * OIDC.setClientInfo( {
 *                          client_id: 'myclientID',
 *                          redirect_uri: 'https://rp.example.com/callback.html'
 *                     }
 *                   );
 */
OIDC.setClientInfo = function(p)
{
    var params = this.supportedClientOptions;

    if(typeof p !== 'undefined') {
        for(var i = 0; i < params.length; i++) {
            if(typeof p[params[i]] !== 'undefined') {
                this[params[i]] = p[params[i]];
            }
        }
    }
    return true;
};


/**
 * Stores the Identity Provider and Client configuration options in the browser session storage for reuse later
 * @function storeInfo
 * @memberof OIDC
 * @param {object} providerInfo    - The Identity Provider's configuration options described in {@link OIDC.supportedProviderOptions}
 * @param {object} clientInfo      - The Client's configuration options described in {@link OIDC.supportedClientOptions}
 */
OIDC.storeInfo = function (providerInfo, clientInfo)
{
    var pOptions = this.supportedProviderOptions;
    var cOptions = this.supportedClientOptions;
    var pInfo = {};
    var cInfo = {};

    if(providerInfo) {
        for(var i = 0; i < pOptions.length; i++) {
            if(typeof providerInfo[pOptions[i]] != 'undefined')
                pInfo[pOptions[i]] = providerInfo[pOptions[i]];
        }
        sessionStorage['providerInfo'] = JSON.stringify(pInfo);
    } else {
        if(sessionStorage['providerInfo'])
            sessionStorage.removeItem('providerInfo');
    }

    if(clientInfo) {
        for(i = 0; i < cOptions.length; i++) {
            if(typeof clientInfo[cOptions[i]] != 'undefined')
                cInfo[cOptions[i]] = clientInfo[cOptions[i]];
        }
        sessionStorage['clientInfo'] = JSON.stringify(cInfo);
    } else {
        if(sessionStorage['clientInfo'])
            sessionStorage.removeItem('clientInfo');
    }
};


/**
 * Load and restore the Identity Provider and Client configuration options from the browser session storage
 * @function restoreInfo
 * @memberof OIDC
 */
OIDC.restoreInfo = function()
{
    var providerInfo = sessionStorage['providerInfo'];
    var clientInfo = sessionStorage['clientInfo'];
    if(providerInfo) {
        this.setProviderInfo(JSON.parse(providerInfo));
    }
    if(clientInfo) {
        this.setClientInfo(JSON.parse(clientInfo));
    }
};

/**
 * Check whether the required configuration parameters are set
 * @function checkRequiredInfo
 * @param {array} params    - List of Identity Provider and client configuration parameters
 * @memberof OIDC
 * @private
 * @return {boolean}        - Indicates whether the options have been set
 *
 */
OIDC.checkRequiredInfo = function(params)
{
    if(params) {
        for(var i = 0; i < params.length; i++) {
            if(!this[params[i]]) {
                throw new OidcException('Required parameter not set - ' + params[i]);
            }
        }
    }
    return true;
};

/**
 * Clears the Identity Provider configuration parameters
 * @function clearProviderInfo
 * @memberof OIDC
 * @private
 */
OIDC.clearProviderInfo = function()
{
    for(var i = 0; i < this.supportedProviderOptions.length; i++) {
        this[this.supportedProviderOptions[i]] = null;
    }
};


/**
 * Redirect to the Identity Provider for authenticaton
 * @param {object} reqOptions    - Optional authentication request options. See {@link OIDC.supportedRequestOptions}
 * @throws {OidcException}
 * @example
 *
 * // login with options
 * OIDC.login( {
 *               scope : 'openid profile',
 *               response_type : 'token id_token',
 *               max_age : 60,
 *               claims : {
 *                          id_token : ['email', 'phone_number'],
 *                          userinfo : ['given_name', 'family_name']
 *                        }
 *              }
 *            );
 *
 * // login with default scope=openid, response_type=id_token
 * OIDC.login();
 */
OIDC.login = function(reqOptions) {
    // verify required parameters
    this.checkRequiredInfo(new Array('client_id', 'redirect_uri', 'authorization_endpoint'));

    var state = null;
    var nonce = null;

    // Replace state and nonce with secure ones if
    var crypto = window.crypto || window.msCrypto;
    if(crypto && crypto.getRandomValues) {
        var D = new Uint32Array(2);
        crypto.getRandomValues(D);
        state = D[0].toString(36);
        nonce = D[1].toString(36);
    } else {
        var byteArrayToLong = function(/*byte[]*/byteArray) {
            var value = 0;
            for ( var i = byteArray.length - 1; i >= 0; i--) {
                value = (value * 256) + byteArray[i];
            }
            return value;
        };

        rng_seed_time();
        var sRandom = new SecureRandom();
        var randState= new Array(4);
        sRandom.nextBytes(randState);
        state = byteArrayToLong(randState).toString(36);

        rng_seed_time();
        var randNonce= new Array(4);
        sRandom.nextBytes(randNonce);
        nonce = byteArrayToLong(randNonce).toString(36);
    }


    // Store the them in session storage
    sessionStorage['state'] = state;
    sessionStorage['nonce'] = nonce;

    var response_type = 'id_token';
    var scope = 'openid';
    var display = null;
    var max_age = null;
    var claims = null;
    var idTokenClaims = {};
    var userInfoClaims = {};

    if(reqOptions) {
        if(reqOptions['response_type']) {
            var parts = reqOptions['response_type'].split(' ');
            var temp = [];
            if(parts) {
                for(var i = 0; i < parts.length; i++) {
                    if(parts[i] == 'code' || parts[i] == 'token' || parts[i] == 'id_token')
                        temp.push(parts[i]);
                }
            }
            if(temp)
                response_type = temp.join(' ');
        }

        if(reqOptions['scope'])
            scope = reqOptions['scope'];
        if(reqOptions['display'])
            display = reqOptions['display'];
        if(reqOptions['max_age'])
            max_age = reqOptions['max_age'];


        if(reqOptions['claims']) {

            if(this['claims_parameter_supported']) {

                if(reqOptions['claims']['id_token']) {
                    for(var j = 0; j < reqOptions['claims']['id_token'].length; j++) {
                        idTokenClaims[reqOptions['claims']['id_token'][j]] = null
                    }
                    if(!claims)
                        claims = {};
                    claims['id_token'] = idTokenClaims;
                }
                if(reqOptions['claims']['userinfo']) {
                    for(var k = 0; k < reqOptions['claims']['userinfo'].length; k++) {
                        userInfoClaims[reqOptions['claims']['userinfo'][k]] = null;
                    }
                    if(!claims)
                        claims = {};
                    claims['userinfo'] = userInfoClaims;
                }

            } else
                throw new OidcException('Provider does not support claims request parameter')

        }
    }

    // Construct the redirect URL
    // For getting an id token, response_type of
    // "token id_token" (note the space), scope of
    // "openid", and some value for nonce is required.
    // client_id must be the consumer key of the connected app.
    // redirect_uri must match the callback URL configured for
    // the connected app.

    var optParams = '';
    if(display)
        optParams += '&display='  + display;
    if(max_age)
        optParams += '&max_age=' + max_age;
    if(claims)
        optParams += '&claims=' + JSON.stringify(claims);

    var url =
        this['authorization_endpoint']
            + '?response_type=' + response_type
            + '&scope=' + scope
            + '&nonce=' + nonce
            + '&client_id=' + this['client_id']
            + '&redirect_uri=' + this['redirect_uri']
            + '&state=' + state
            + optParams;


    window.location.replace(url);
};


/**
 * Verifies the ID Token signature using the JWK Keyset from jwks or jwks_uri of the
 * Identity Provider Configuration options set via {@link OIDC.setProviderInfo}.
 * Supports only RSA signatures
 * @param {string }idtoken      - The ID Token string
 * @returns {boolean}           Indicates whether the signature is valid or not
 * @see OIDC.setProviderInfo
 * @throws {OidcException}
 */
OIDC.verifyIdTokenSig = function (idtoken)
{
    var verified = false;
    var requiredParam = this['jwks_uri'] || this['jwks'];
    if(!requiredParam) {
        throw new OidcException('jwks_uri or jwks parameter not set');
    } else  if(idtoken) {
        var idtParts = this.getIdTokenParts(idtoken);
        var header = this.getJsonObject(idtParts[0])
        var jwks = this['jwks'] || this.fetchJSON(this['jwks_uri']);
        if(!jwks)
            throw new OidcException('No JWK keyset');
        else {
            if(header['alg'] && header['alg'].substr(0, 2) == 'RS') {
                var jwk = this.jwk_get_key(jwks, 'RSA', 'sig', header['kid']);
                if(!jwk)
                    new OidcException('No matching JWK found');
                else {
                    verified = this.rsaVerifyJWS(idtoken, jwk[0]);
                }
            } else
                throw new OidcException('Unsupported JWS signature algorithm ' + header['alg']);
        }
    }
    return verified;
}


/**
 * Validates the information in the ID Token against configuration data in the Identity Provider
 * and Client configuration set via {@link OIDC.setProviderInfo} and set via {@link OIDC.setClientInfo}
 * @param {string} idtoken      - The ID Token string
 * @returns {boolean}           Validity of the ID Token
 * @throws {OidcException}
 */
OIDC.isValidIdToken = function(idtoken) {

    var idt = null;
    var valid = false;
    this.checkRequiredInfo(['issuer', 'client_id']);

    if(idtoken) {
        var idtParts = this.getIdTokenParts(idtoken);
        var payload = this.getJsonObject(idtParts[1])
        if(payload) {
            var now =  new Date() / 1000;
            if( payload['iat'] >  now + (5 * 60))
                throw new OidcException('ID Token issued time is later than current time');
            if(payload['exp'] < now - (5*60))
                throw new OidcException('ID Token expired');
            var audience = null;
            if(payload['aud']) {
                if(payload['aud'] instanceof Array) {
                    audience = payload['aud'][0];
                } else
                    audience = payload['aud'];
            }
            if(audience != this['client_id'])
                throw new OidcException('invalid audience');
            if(payload['iss'] != this['issuer'])
                throw new OidcException('invalid issuer ' + payload['iss'] + ' != ' + this['issuer']);
            if(payload['nonce'] != sessionStorage['nonce'])
                throw new OidcException('invalid nonce');
            valid = true;
        } else
            throw new OidcException('Unable to parse JWS payload');
    }
    return valid;
}

/**
 * Verifies the JWS string using the JWK
 * @param {string} jws      - The JWS string
 * @param {object} jwk      - The JWK Key that will be used to verify the signature
 * @returns {boolean}       Validity of the JWS signature
 * @throws {OidcException}
 */
OIDC.rsaVerifyJWS = function (jws, jwk)
{
    if(jws && typeof jwk === 'object') {
        if(jwk['kty'] == 'RSA') {
            var verifier = new KJUR.jws.JWS();
            if(jwk['n'] && jwk['e']) {
                var keyN = b64utohex(jwk['n']);
                var keyE = b64utohex(jwk['e']);
                return verifier.verifyJWSByNE(jws, keyN, keyE);
            } else if (jwk['x5c']) {
                return verifier.verifyJWSByPemX509Cert(jws, "-----BEGIN CERTIFICATE-----\n" + jwk['x5c'][0] + "\n-----END CERTIFICATE-----\n");
            }
        } else {
            throw new OidcException('No RSA kty in JWK');
        }
    }
    return false;
}

/**
 * Get the ID Token from the current page URL whose signature is verified and contents validated
 * against the configuration data set via {@link OIDC.setProviderInfo} and {@link OIDC.setClientInfo}
 * @returns {string|null}
 * @throws {OidcException}
 */
OIDC.getValidIdToken = function()
{
    var url = window.location.href;

    // Check if there was an error parameter
    var error = url.match('[?&]error=([^&]*)')
    if (error) {
        // If so, extract the error description and display it
        var description = url.match('[?&]error_description=([^&]*)');
        throw new OidcException(error[1] + ' Description: ' + description[1]);
    }
    // Exract state from the state parameter
    var smatch = url.match('[?&]state=([^&]*)');
    if (smatch) {
        var state = smatch[1] ;
        var sstate = sessionStorage['state'];
        var badstate = (state != sstate);
    }

    // Extract id token from the id_token parameter
    var match = url.match('[?&]id_token=([^&]*)');
    if (badstate) {
        throw new OidcException("State mismatch");
    } else if (match) {
        var id_token = match[1]; // String captured by ([^&]*)

        if (id_token) {
            var sigVerified = this.verifyIdTokenSig(id_token);
            var valid = this.isValidIdToken(id_token);
            if(sigVerified && valid)
                return id_token;
        } else {
            throw new OidcException('Could not retrieve ID Token from the URL');
        }
    } else {
        throw new OidcException('No ID Token returned');
    }
    return null;
};


/**
 * Get Access Token from the current page URL
 *
 * @returns {string|null}  Access Token
 */
OIDC.getAccessToken = function()
{
    var url = window.location.href;

    // Check for token
    var token = url.match('[?&]access_token=([^&]*)');
    if (token)
        return token[1];
    else
        return null;
}


/**
 * Get Authorization Code from the current page URL
 *
 * @returns {string|null}  Authorization Code
 */
OIDC.getCode = function()
{
    var url = window.location.href;

    // Check for code
    var code = url.match('[?&]code=([^(&)]*)');
    if (code) {
        return code[1];
    }
}


/**
 * Splits the ID Token string into the individual JWS parts
 * @param  {string} id_token    - ID Token
 * @returns {Array} An array of the JWS compact serialization components (header, payload, signature)
 */
OIDC.getIdTokenParts = function (id_token) {
    var jws = new KJUR.jws.JWS();
    jws.parseJWS(id_token);
    return new Array(jws.parsedJWS.headS, jws.parsedJWS.payloadS, jws.parsedJWS.si);
};

/**
 * Get the contents of the ID Token payload as an JSON object
 * @param {string} id_token     - ID Token
 * @returns {object}            - The ID Token payload JSON object
 */
OIDC.getIdTokenPayload = function (id_token) {
    var parts = this.getIdTokenParts(id_token);
    if(parts)
        return this.getJsonObject(parts[1]);
}

/**
 * Get the JSON object from the JSON string
 * @param {string} jsonS    - JSON string
 * @returns {object|null}   JSON object or null
 */
OIDC.getJsonObject = function (jsonS) {
    var jws = KJUR.jws.JWS;
    if(jws.isSafeJSONString(jsonS)) {
        return jws.readSafeJSONString(jsonS);
    }
    return null;
//    return JSON.parse(jsonS);
};


/**
 * Retrieves the JSON file at the specified URL. The URL must have CORS enabled for this function to work.
 * @param {string} url      - URL to fetch the JSON file
 * @returns {string|null}    contents of the URL or null
 * @throws {OidcException}
 */
OIDC.fetchJSON = function(url) {
    try {
        var request = new XMLHttpRequest();
        request.open('GET', url, false);
        request.send(null);

        if (request.status === 200) {
            return request.responseText;
        } else
            throw new OidcException("fetchJSON - " + request.status + ' ' + request.statusText);

    }
    catch(e) {
        throw new OidcException('Unable to retrieve JSON file at ' + url + ' : ' + e.toString());
    }
    return null;
};

/**
 * Retrieve the JWK key that matches the input criteria
 * @param {string|object} jwkIn     - JWK Keyset string or object
 * @param {string} kty              - The 'kty' to match (RSA|EC). Only RSA is supported.
 * @param {string}use               - The 'use' to match (sig|enc).
 * @param {string}kid               - The 'kid' to match
 * @returns {array}                 Array of JWK keys that match the specified criteria                                                                     itera
 */
OIDC.jwk_get_key = function(jwkIn, kty, use, kid )
{
    var jwk = null;
    var foundKeys = [];

    if(jwkIn) {
        if(typeof jwkIn === 'string')
            jwk = this.getJsonObject(jwkIn);
        else if(typeof jwkIn === 'object')
            jwk = jwkIn;

        if(jwk != null) {
            if(typeof jwk['keys'] === 'object') {
                if(jwk.keys.length == 0)
                    return null;

                for(var i = 0; i < jwk.keys.length; i++) {
                    if(jwk['keys'][i]['kty'] == kty)
                        foundKeys.push(jwk.keys[i]);
                }

                if(foundKeys.length == 0)
                    return null;

                if(use) {
                    var temp = [];
                    for(var j = 0; j < foundKeys.length; j++) {
                        if(!foundKeys[j]['use'])
                            temp.push(foundKeys[j]);
                        else if(foundKeys[j]['use'] == use)
                            temp.push(foundKeys[j]);
                    }
                    foundKeys = temp;
                }
                if(foundKeys.length == 0)
                    return null;

                if(kid) {
                    temp = [];
                    for(var k = 0; k < foundKeys.length; k++) {
                        if(foundKeys[k]['kid'] == kid)
                            temp.push(foundKeys[k]);
                    }
                    foundKeys = temp;
                }
                if(foundKeys.length == 0)
                    return null;
                else
                    return foundKeys;
            }
        }

    }

};

/**
 * Performs discovery on the IdP issuer_id (OIDC.discover)
 * @function discover
 * @memberof OIDC
 * @param {string} issuer     - The Identity Provider's issuer_id
 * @returns {object|null}     - The JSON object of the discovery document or null
 * @throws {OidcException}
 */
OIDC.discover = function(issuer)
{
    var discovery = null;
    if(issuer) {
        var openidConfig = issuer + '/.well-known/openid-configuration';
        var discoveryDoc = this.fetchJSON(openidConfig);
        if(discoveryDoc)
            discovery = this.getJsonObject(discoveryDoc)
    }
    return discovery;
};


/**
 * OidcException
 * @param {string } message  - The exception error message
 * @constructor
 */
function OidcException(message) {
    this.name = 'OidcException';
    this.message = message;
}
OidcException.prototype = new Error();
OidcException.prototype.constructor = OidcException;



function namespace(namespaceString) {
    var parts = namespaceString.split('.'),
        parent = window,
        currentPart = '';

    for(var i = 0, length = parts.length; i < length; i++) {
        currentPart = parts[i];
        parent[currentPart] = parent[currentPart] || {};
        parent = parent[currentPart];
    }
    return parent;
}

/*  core.js  */
/*
CryptoJS v3.1.9
https://github.com/brix/crypto-js
(c) 2009-2013 by Jeff Mott. (c) 2013-2016 Evan Vosberg. All rights reserved.
https://github.com/brix/crypto-js
*/

var CryptoJS = CryptoJS || (function (Math, undefined) {var create = Object.create || (function () {       function F() {};

        return function (obj) {
            var subtype;

            F.prototype = obj;

            subtype = new F();

            F.prototype = null;

            return subtype;
        };
    }())

    /**
     * CryptoJS namespace.
     */
    var C = {};

    /**
     * Library namespace.
     */
    var C_lib = C.lib = {};

    /**
     * Base object for prototypal inheritance.
     */
    var Base = C_lib.Base = (function () {


        return {
            /**
             * Creates a new object that inherits from this object.
             *
             * @param {Object} overrides Properties to copy into the new object.
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         field: 'value',
             *
             *         method: function () {
             *         }
             *     });
             */
            extend: function (overrides) {
                // Spawn
                var subtype = create(this);

                // Augment
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                // Create default initializer
                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
                    subtype.init = function () {
                        subtype.$super.init.apply(this, arguments);
                    };
                }

                // Initializer's prototype is the subtype object
                subtype.init.prototype = subtype;

                // Reference supertype
                subtype.$super = this;

                return subtype;
            },

            /**
             * Extends this object and runs the init method.
             * Arguments to create() will be passed to init().
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var instance = MyType.create();
             */
            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);

                return instance;
            },

            /**
             * Initializes a newly created object.
             * Override this method to add some logic when your objects are created.
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         init: function () {
             *             // ...
             *         }
             *     });
             */
            init: function () {
            },

            /**
             * Copies properties into this object.
             *
             * @param {Object} properties The properties to mix in.
             *
             * @example
             *
             *     MyType.mixIn({
             *         field: 'value'
             *     });
             */
            mixIn: function (properties) {
                for (var propertyName in properties) {
                    if (properties.hasOwnProperty(propertyName)) {
                        this[propertyName] = properties[propertyName];
                    }
                }

                // IE won't copy toString using the loop above
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            /**
             * Creates a copy of this object.
             *
             * @return {Object} The clone.
             *
             * @example
             *
             *     var clone = instance.clone();
             */
            clone: function () {
                return this.init.prototype.extend(this);
            }
        };
    }());

    /**
     * An array of 32-bit words.
     *
     * @property {Array} words The array of 32-bit words.
     * @property {number} sigBytes The number of significant bytes in this word array.
     */
    var WordArray = C_lib.WordArray = Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        toString: function (encoder) {
            return (encoder || Hex).stringify(this);
        },

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */
        concat: function (wordArray) {
            // Shortcuts
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;

            // Clamp excess bits
            this.clamp();

            // Concat
            if (thisSigBytes % 4) {
                // Copy one byte at a time
                for (var i = 0; i < thatSigBytes; i++) {
                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                }
            } else {
                // Copy one word at a time
                for (var i = 0; i < thatSigBytes; i += 4) {
                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                }
            }
            this.sigBytes += thatSigBytes;

            // Chainable
            return this;
        },

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */
        clamp: function () {
            // Shortcuts
            var words = this.words;
            var sigBytes = this.sigBytes;

            // Clamp
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        random: function (nBytes) {
            var words = [];

            var r = (function (m_w) {
                var m_w = m_w;
                var m_z = 0x3ade68b1;
                var mask = 0xffffffff;

                return function () {
                    m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
                    m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
                    var result = ((m_z << 0x10) + m_w) & mask;
                    result /= 0x100000000;
                    result += 0.5;
                    return result * (Math.random() > .5 ? 1 : -1);
                }
            });

            for (var i = 0, rcache; i < nBytes; i += 4) {
                var _r = r((rcache || Math.random()) * 0x100000000);

                rcache = _r() * 0x3ade67b7;
                words.push((_r() * 0x100000000) | 0);
            }

            return new WordArray.init(words, nBytes);
        }
    });

    /**
     * Encoder namespace.
     */
    var C_enc = C.enc = {};

    /**
     * Hex encoding strategy.
     */
    var Hex = C_enc.Hex = {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var hexChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function (hexStr) {
            // Shortcut
            var hexStrLength = hexStr.length;

            // Convert
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return new WordArray.init(words, hexStrLength / 2);
        }
    };

    /**
     * Latin1 encoding strategy.
     */
    var Latin1 = C_enc.Latin1 = {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var latin1Chars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Chars.push(String.fromCharCode(bite));
            }

            return latin1Chars.join('');
        },

        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function (latin1Str) {
            // Shortcut
            var latin1StrLength = latin1Str.length;

            // Convert
            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }

            return new WordArray.init(words, latin1StrLength);
        }
    };

    /**
     * UTF-8 encoding strategy.
     */
    var Utf8 = C_enc.Utf8 = {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function (wordArray) {
            try {
                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
            } catch (e) {
                throw new Error('Malformed UTF-8 data');
            }
        },

        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function (utf8Str) {
            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
    };

    /**
     * Abstract buffered block algorithm template.
     *
     * The property blockSize must be implemented in a concrete subtype.
     *
     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
     */
    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        reset: function () {
            // Initial values
            this._data = new WordArray.init();
            this._nDataBytes = 0;
        },

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */
        _append: function (data) {
            // Convert string to WordArray, else assume WordArray already
            if (typeof data == 'string') {
                data = Utf8.parse(data);
            }

            // Append
            this._data.concat(data);
            this._nDataBytes += data.sigBytes;
        },

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */
        _process: function (doFlush) {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;
            var dataSigBytes = data.sigBytes;
            var blockSize = this.blockSize;
            var blockSizeBytes = blockSize * 4;

            // Count blocks ready
            var nBlocksReady = dataSigBytes / blockSizeBytes;
            if (doFlush) {
                // Round up to include partial blocks
                nBlocksReady = Math.ceil(nBlocksReady);
            } else {
                // Round down to include only full blocks,
                // less the number of blocks that must remain in the buffer
                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
            }

            // Count words ready
            var nWordsReady = nBlocksReady * blockSize;

            // Count bytes ready
            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

            // Process blocks
            if (nWordsReady) {
                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    // Perform concrete-algorithm logic
                    this._doProcessBlock(dataWords, offset);
                }

                // Remove processed words
                var processedWords = dataWords.splice(0, nWordsReady);
                data.sigBytes -= nBytesReady;
            }

            // Return processed words
            return new WordArray.init(processedWords, nBytesReady);
        },

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone._data = this._data.clone();

            return clone;
        },

        _minBufferSize: 0
    });

    /**
     * Abstract hasher template.
     *
     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
     */
    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
        /**
         * Configuration options.
         */
        cfg: Base.extend(),

        /**
         * Initializes a newly created hasher.
         *
         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
         *
         * @example
         *
         *     var hasher = CryptoJS.algo.SHA256.create();
         */
        init: function (cfg) {
            // Apply config defaults
            this.cfg = this.cfg.extend(cfg);

            // Set initial values
            this.reset();
        },

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */
        reset: function () {
            // Reset data buffer
            BufferedBlockAlgorithm.reset.call(this);

            // Perform concrete-hasher logic
            this._doReset();
        },

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */
        update: function (messageUpdate) {
            // Append
            this._append(messageUpdate);

            // Update the hash
            this._process();

            // Chainable
            return this;
        },

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */
        finalize: function (messageUpdate) {
            // Final message update
            if (messageUpdate) {
                this._append(messageUpdate);
            }

            // Perform concrete-hasher logic
            var hash = this._doFinalize();

            return hash;
        },

        blockSize: 512/32,

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} hasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return new hasher.init(cfg).finalize(message);
            };
        },

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} hasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return new C_algo.HMAC.init(hasher, key).finalize(message);
            };
        }
    });

    /**
     * Algorithm namespace.
     */
    var C_algo = C.algo = {};

    return C;
}(Math));

/*  sha1-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){var k=CryptoJS,b=k.lib,m=b.WordArray,l=b.Hasher,d=[],b=k.algo.SHA1=l.extend({_doReset:function(){this._hash=new m.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(n,p){for(var a=this._hash.words,e=a[0],f=a[1],h=a[2],j=a[3],b=a[4],c=0;80>c;c++){if(16>c)d[c]=n[p+c]|0;else{var g=d[c-3]^d[c-8]^d[c-14]^d[c-16];d[c]=g<<1|g>>>31}g=(e<<5|e>>>27)+b+d[c];g=20>c?g+((f&h|~f&j)+1518500249):40>c?g+((f^h^j)+1859775393):60>c?g+((f&h|f&j|h&j)-1894007588):g+((f^h^
j)-899497514);b=j;j=h;h=f<<30|f>>>2;f=e;e=g}a[0]=a[0]+e|0;a[1]=a[1]+f|0;a[2]=a[2]+h|0;a[3]=a[3]+j|0;a[4]=a[4]+b|0},_doFinalize:function(){var b=this._data,d=b.words,a=8*this._nDataBytes,e=8*b.sigBytes;d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=Math.floor(a/4294967296);d[(e+64>>>9<<4)+15]=a;b.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var b=l.clone.call(this);b._hash=this._hash.clone();return b}});k.SHA1=l._createHelper(b);k.HmacSHA1=l._createHmacHelper(b)})();

/*  sha256-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(k){for(var g=CryptoJS,h=g.lib,v=h.WordArray,j=h.Hasher,h=g.algo,s=[],t=[],u=function(q){return 4294967296*(q-(q|0))|0},l=2,b=0;64>b;){var d;a:{d=l;for(var w=k.sqrt(d),r=2;r<=w;r++)if(!(d%r)){d=!1;break a}d=!0}d&&(8>b&&(s[b]=u(k.pow(l,0.5))),t[b]=u(k.pow(l,1/3)),b++);l++}var n=[],h=h.SHA256=j.extend({_doReset:function(){this._hash=new v.init(s.slice(0))},_doProcessBlock:function(q,h){for(var a=this._hash.words,c=a[0],d=a[1],b=a[2],k=a[3],f=a[4],g=a[5],j=a[6],l=a[7],e=0;64>e;e++){if(16>e)n[e]=
q[h+e]|0;else{var m=n[e-15],p=n[e-2];n[e]=((m<<25|m>>>7)^(m<<14|m>>>18)^m>>>3)+n[e-7]+((p<<15|p>>>17)^(p<<13|p>>>19)^p>>>10)+n[e-16]}m=l+((f<<26|f>>>6)^(f<<21|f>>>11)^(f<<7|f>>>25))+(f&g^~f&j)+t[e]+n[e];p=((c<<30|c>>>2)^(c<<19|c>>>13)^(c<<10|c>>>22))+(c&d^c&b^d&b);l=j;j=g;g=f;f=k+m|0;k=b;b=d;d=c;c=m+p|0}a[0]=a[0]+c|0;a[1]=a[1]+d|0;a[2]=a[2]+b|0;a[3]=a[3]+k|0;a[4]=a[4]+f|0;a[5]=a[5]+g|0;a[6]=a[6]+j|0;a[7]=a[7]+l|0},_doFinalize:function(){var d=this._data,b=d.words,a=8*this._nDataBytes,c=8*d.sigBytes;
b[c>>>5]|=128<<24-c%32;b[(c+64>>>9<<4)+14]=k.floor(a/4294967296);b[(c+64>>>9<<4)+15]=a;d.sigBytes=4*b.length;this._process();return this._hash},clone:function(){var b=j.clone.call(this);b._hash=this._hash.clone();return b}});g.SHA256=j._createHelper(h);g.HmacSHA256=j._createHmacHelper(h)})(Math);

/*  x64-core-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(g){var a=CryptoJS,f=a.lib,e=f.Base,h=f.WordArray,a=a.x64={};a.Word=e.extend({init:function(b,c){this.high=b;this.low=c}});a.WordArray=e.extend({init:function(b,c){b=this.words=b||[];this.sigBytes=c!=g?c:8*b.length},toX32:function(){for(var b=this.words,c=b.length,a=[],d=0;d<c;d++){var e=b[d];a.push(e.high);a.push(e.low)}return h.create(a,this.sigBytes)},clone:function(){for(var b=e.clone.call(this),c=b.words=this.words.slice(0),a=c.length,d=0;d<a;d++)c[d]=c[d].clone();return b}})})();

/*  sha512-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){function a(){return d.create.apply(d,arguments)}for(var n=CryptoJS,r=n.lib.Hasher,e=n.x64,d=e.Word,T=e.WordArray,e=n.algo,ea=[a(1116352408,3609767458),a(1899447441,602891725),a(3049323471,3964484399),a(3921009573,2173295548),a(961987163,4081628472),a(1508970993,3053834265),a(2453635748,2937671579),a(2870763221,3664609560),a(3624381080,2734883394),a(310598401,1164996542),a(607225278,1323610764),a(1426881987,3590304994),a(1925078388,4068182383),a(2162078206,991336113),a(2614888103,633803317),
a(3248222580,3479774868),a(3835390401,2666613458),a(4022224774,944711139),a(264347078,2341262773),a(604807628,2007800933),a(770255983,1495990901),a(1249150122,1856431235),a(1555081692,3175218132),a(1996064986,2198950837),a(2554220882,3999719339),a(2821834349,766784016),a(2952996808,2566594879),a(3210313671,3203337956),a(3336571891,1034457026),a(3584528711,2466948901),a(113926993,3758326383),a(338241895,168717936),a(666307205,1188179964),a(773529912,1546045734),a(1294757372,1522805485),a(1396182291,
2643833823),a(1695183700,2343527390),a(1986661051,1014477480),a(2177026350,1206759142),a(2456956037,344077627),a(2730485921,1290863460),a(2820302411,3158454273),a(3259730800,3505952657),a(3345764771,106217008),a(3516065817,3606008344),a(3600352804,1432725776),a(4094571909,1467031594),a(275423344,851169720),a(430227734,3100823752),a(506948616,1363258195),a(659060556,3750685593),a(883997877,3785050280),a(958139571,3318307427),a(1322822218,3812723403),a(1537002063,2003034995),a(1747873779,3602036899),
a(1955562222,1575990012),a(2024104815,1125592928),a(2227730452,2716904306),a(2361852424,442776044),a(2428436474,593698344),a(2756734187,3733110249),a(3204031479,2999351573),a(3329325298,3815920427),a(3391569614,3928383900),a(3515267271,566280711),a(3940187606,3454069534),a(4118630271,4000239992),a(116418474,1914138554),a(174292421,2731055270),a(289380356,3203993006),a(460393269,320620315),a(685471733,587496836),a(852142971,1086792851),a(1017036298,365543100),a(1126000580,2618297676),a(1288033470,
3409855158),a(1501505948,4234509866),a(1607167915,987167468),a(1816402316,1246189591)],v=[],w=0;80>w;w++)v[w]=a();e=e.SHA512=r.extend({_doReset:function(){this._hash=new T.init([new d.init(1779033703,4089235720),new d.init(3144134277,2227873595),new d.init(1013904242,4271175723),new d.init(2773480762,1595750129),new d.init(1359893119,2917565137),new d.init(2600822924,725511199),new d.init(528734635,4215389547),new d.init(1541459225,327033209)])},_doProcessBlock:function(a,d){for(var f=this._hash.words,
F=f[0],e=f[1],n=f[2],r=f[3],G=f[4],H=f[5],I=f[6],f=f[7],w=F.high,J=F.low,X=e.high,K=e.low,Y=n.high,L=n.low,Z=r.high,M=r.low,$=G.high,N=G.low,aa=H.high,O=H.low,ba=I.high,P=I.low,ca=f.high,Q=f.low,k=w,g=J,z=X,x=K,A=Y,y=L,U=Z,B=M,l=$,h=N,R=aa,C=O,S=ba,D=P,V=ca,E=Q,m=0;80>m;m++){var s=v[m];if(16>m)var j=s.high=a[d+2*m]|0,b=s.low=a[d+2*m+1]|0;else{var j=v[m-15],b=j.high,p=j.low,j=(b>>>1|p<<31)^(b>>>8|p<<24)^b>>>7,p=(p>>>1|b<<31)^(p>>>8|b<<24)^(p>>>7|b<<25),u=v[m-2],b=u.high,c=u.low,u=(b>>>19|c<<13)^(b<<
3|c>>>29)^b>>>6,c=(c>>>19|b<<13)^(c<<3|b>>>29)^(c>>>6|b<<26),b=v[m-7],W=b.high,t=v[m-16],q=t.high,t=t.low,b=p+b.low,j=j+W+(b>>>0<p>>>0?1:0),b=b+c,j=j+u+(b>>>0<c>>>0?1:0),b=b+t,j=j+q+(b>>>0<t>>>0?1:0);s.high=j;s.low=b}var W=l&R^~l&S,t=h&C^~h&D,s=k&z^k&A^z&A,T=g&x^g&y^x&y,p=(k>>>28|g<<4)^(k<<30|g>>>2)^(k<<25|g>>>7),u=(g>>>28|k<<4)^(g<<30|k>>>2)^(g<<25|k>>>7),c=ea[m],fa=c.high,da=c.low,c=E+((h>>>14|l<<18)^(h>>>18|l<<14)^(h<<23|l>>>9)),q=V+((l>>>14|h<<18)^(l>>>18|h<<14)^(l<<23|h>>>9))+(c>>>0<E>>>0?1:
0),c=c+t,q=q+W+(c>>>0<t>>>0?1:0),c=c+da,q=q+fa+(c>>>0<da>>>0?1:0),c=c+b,q=q+j+(c>>>0<b>>>0?1:0),b=u+T,s=p+s+(b>>>0<u>>>0?1:0),V=S,E=D,S=R,D=C,R=l,C=h,h=B+c|0,l=U+q+(h>>>0<B>>>0?1:0)|0,U=A,B=y,A=z,y=x,z=k,x=g,g=c+b|0,k=q+s+(g>>>0<c>>>0?1:0)|0}J=F.low=J+g;F.high=w+k+(J>>>0<g>>>0?1:0);K=e.low=K+x;e.high=X+z+(K>>>0<x>>>0?1:0);L=n.low=L+y;n.high=Y+A+(L>>>0<y>>>0?1:0);M=r.low=M+B;r.high=Z+U+(M>>>0<B>>>0?1:0);N=G.low=N+h;G.high=$+l+(N>>>0<h>>>0?1:0);O=H.low=O+C;H.high=aa+R+(O>>>0<C>>>0?1:0);P=I.low=P+D;
I.high=ba+S+(P>>>0<D>>>0?1:0);Q=f.low=Q+E;f.high=ca+V+(Q>>>0<E>>>0?1:0)},_doFinalize:function(){var a=this._data,d=a.words,f=8*this._nDataBytes,e=8*a.sigBytes;d[e>>>5]|=128<<24-e%32;d[(e+128>>>10<<5)+30]=Math.floor(f/4294967296);d[(e+128>>>10<<5)+31]=f;a.sigBytes=4*d.length;this._process();return this._hash.toX32()},clone:function(){var a=r.clone.call(this);a._hash=this._hash.clone();return a},blockSize:32});n.SHA512=r._createHelper(e);n.HmacSHA512=r._createHmacHelper(e)})();

/*  sha384-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){var c=CryptoJS,a=c.x64,b=a.Word,e=a.WordArray,a=c.algo,d=a.SHA512,a=a.SHA384=d.extend({_doReset:function(){this._hash=new e.init([new b.init(3418070365,3238371032),new b.init(1654270250,914150663),new b.init(2438529370,812702999),new b.init(355462360,4144912697),new b.init(1731405415,4290775857),new b.init(2394180231,1750603025),new b.init(3675008525,1694076839),new b.init(1203062813,3204075428)])},_doFinalize:function(){var a=d._doFinalize.call(this);a.sigBytes-=16;return a}});c.SHA384=
d._createHelper(a);c.HmacSHA384=d._createHmacHelper(a)})();

/*  base64-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";var b64pad="=";function hex2b64(d){var b;var e;var a="";for(b=0;b+3<=d.length;b+=3){e=parseInt(d.substring(b,b+3),16);a+=b64map.charAt(e>>6)+b64map.charAt(e&63)}if(b+1==d.length){e=parseInt(d.substring(b,b+1),16);a+=b64map.charAt(e<<2)}else{if(b+2==d.length){e=parseInt(d.substring(b,b+2),16);a+=b64map.charAt(e>>2)+b64map.charAt((e&3)<<4)}}if(b64pad){while((a.length&3)>0){a+=b64pad}}return a}function b64tohex(f){var d="";var e;var b=0;var c;var a;for(e=0;e<f.length;++e){if(f.charAt(e)==b64pad){break}a=b64map.indexOf(f.charAt(e));if(a<0){continue}if(b==0){d+=int2char(a>>2);c=a&3;b=1}else{if(b==1){d+=int2char((c<<2)|(a>>4));c=a&15;b=2}else{if(b==2){d+=int2char(c);d+=int2char(a>>2);c=a&3;b=3}else{d+=int2char((c<<2)|(a>>4));d+=int2char(a&15);b=0}}}}if(b==1){d+=int2char(c<<2)}return d}function b64toBA(e){var d=b64tohex(e);var c;var b=new Array();for(c=0;2*c<d.length;++c){b[c]=parseInt(d.substring(2*c,2*c+2),16)}return b};
/*  jsbn-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var dbits;var canary=244837814094590;var j_lm=((canary&16777215)==15715070);function BigInteger(e,d,f){if(e!=null){if("number"==typeof e){this.fromNumber(e,d,f)}else{if(d==null&&"string"!=typeof e){this.fromString(e,256)}else{this.fromString(e,d)}}}}function nbi(){return new BigInteger(null)}function am1(f,a,b,e,h,g){while(--g>=0){var d=a*this[f++]+b[e]+h;h=Math.floor(d/67108864);b[e++]=d&67108863}return h}function am2(f,q,r,e,o,a){var k=q&32767,p=q>>15;while(--a>=0){var d=this[f]&32767;var g=this[f++]>>15;var b=p*d+g*k;d=k*d+((b&32767)<<15)+r[e]+(o&1073741823);o=(d>>>30)+(b>>>15)+p*g+(o>>>30);r[e++]=d&1073741823}return o}function am3(f,q,r,e,o,a){var k=q&16383,p=q>>14;while(--a>=0){var d=this[f]&16383;var g=this[f++]>>14;var b=p*d+g*k;d=k*d+((b&16383)<<14)+r[e]+o;o=(d>>28)+(b>>14)+p*g;r[e++]=d&268435455}return o}if(j_lm&&(navigator.appName=="Microsoft Internet Explorer")){BigInteger.prototype.am=am2;dbits=30}else{if(j_lm&&(navigator.appName!="Netscape")){BigInteger.prototype.am=am1;dbits=26}else{BigInteger.prototype.am=am3;dbits=28}}BigInteger.prototype.DB=dbits;BigInteger.prototype.DM=((1<<dbits)-1);BigInteger.prototype.DV=(1<<dbits);var BI_FP=52;BigInteger.prototype.FV=Math.pow(2,BI_FP);BigInteger.prototype.F1=BI_FP-dbits;BigInteger.prototype.F2=2*dbits-BI_FP;var BI_RM="0123456789abcdefghijklmnopqrstuvwxyz";var BI_RC=new Array();var rr,vv;rr="0".charCodeAt(0);for(vv=0;vv<=9;++vv){BI_RC[rr++]=vv}rr="a".charCodeAt(0);for(vv=10;vv<36;++vv){BI_RC[rr++]=vv}rr="A".charCodeAt(0);for(vv=10;vv<36;++vv){BI_RC[rr++]=vv}function int2char(a){return BI_RM.charAt(a)}function intAt(b,a){var d=BI_RC[b.charCodeAt(a)];return(d==null)?-1:d}function bnpCopyTo(b){for(var a=this.t-1;a>=0;--a){b[a]=this[a]}b.t=this.t;b.s=this.s}function bnpFromInt(a){this.t=1;this.s=(a<0)?-1:0;if(a>0){this[0]=a}else{if(a<-1){this[0]=a+this.DV}else{this.t=0}}}function nbv(a){var b=nbi();b.fromInt(a);return b}function bnpFromString(h,c){var e;if(c==16){e=4}else{if(c==8){e=3}else{if(c==256){e=8}else{if(c==2){e=1}else{if(c==32){e=5}else{if(c==4){e=2}else{this.fromRadix(h,c);return}}}}}}this.t=0;this.s=0;var g=h.length,d=false,f=0;while(--g>=0){var a=(e==8)?h[g]&255:intAt(h,g);if(a<0){if(h.charAt(g)=="-"){d=true}continue}d=false;if(f==0){this[this.t++]=a}else{if(f+e>this.DB){this[this.t-1]|=(a&((1<<(this.DB-f))-1))<<f;this[this.t++]=(a>>(this.DB-f))}else{this[this.t-1]|=a<<f}}f+=e;if(f>=this.DB){f-=this.DB}}if(e==8&&(h[0]&128)!=0){this.s=-1;if(f>0){this[this.t-1]|=((1<<(this.DB-f))-1)<<f}}this.clamp();if(d){BigInteger.ZERO.subTo(this,this)}}function bnpClamp(){var a=this.s&this.DM;while(this.t>0&&this[this.t-1]==a){--this.t}}function bnToString(c){if(this.s<0){return"-"+this.negate().toString(c)}var e;if(c==16){e=4}else{if(c==8){e=3}else{if(c==2){e=1}else{if(c==32){e=5}else{if(c==4){e=2}else{return this.toRadix(c)}}}}}var g=(1<<e)-1,l,a=false,h="",f=this.t;var j=this.DB-(f*this.DB)%e;if(f-->0){if(j<this.DB&&(l=this[f]>>j)>0){a=true;h=int2char(l)}while(f>=0){if(j<e){l=(this[f]&((1<<j)-1))<<(e-j);l|=this[--f]>>(j+=this.DB-e)}else{l=(this[f]>>(j-=e))&g;if(j<=0){j+=this.DB;--f}}if(l>0){a=true}if(a){h+=int2char(l)}}}return a?h:"0"}function bnNegate(){var a=nbi();BigInteger.ZERO.subTo(this,a);return a}function bnAbs(){return(this.s<0)?this.negate():this}function bnCompareTo(b){var d=this.s-b.s;if(d!=0){return d}var c=this.t;d=c-b.t;if(d!=0){return(this.s<0)?-d:d}while(--c>=0){if((d=this[c]-b[c])!=0){return d}}return 0}function nbits(a){var c=1,b;if((b=a>>>16)!=0){a=b;c+=16}if((b=a>>8)!=0){a=b;c+=8}if((b=a>>4)!=0){a=b;c+=4}if((b=a>>2)!=0){a=b;c+=2}if((b=a>>1)!=0){a=b;c+=1}return c}function bnBitLength(){if(this.t<=0){return 0}return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM))}function bnpDLShiftTo(c,b){var a;for(a=this.t-1;a>=0;--a){b[a+c]=this[a]}for(a=c-1;a>=0;--a){b[a]=0}b.t=this.t+c;b.s=this.s}function bnpDRShiftTo(c,b){for(var a=c;a<this.t;++a){b[a-c]=this[a]}b.t=Math.max(this.t-c,0);b.s=this.s}function bnpLShiftTo(j,e){var b=j%this.DB;var a=this.DB-b;var g=(1<<a)-1;var f=Math.floor(j/this.DB),h=(this.s<<b)&this.DM,d;for(d=this.t-1;d>=0;--d){e[d+f+1]=(this[d]>>a)|h;h=(this[d]&g)<<b}for(d=f-1;d>=0;--d){e[d]=0}e[f]=h;e.t=this.t+f+1;e.s=this.s;e.clamp()}function bnpRShiftTo(g,d){d.s=this.s;var e=Math.floor(g/this.DB);if(e>=this.t){d.t=0;return}var b=g%this.DB;var a=this.DB-b;var f=(1<<b)-1;d[0]=this[e]>>b;for(var c=e+1;c<this.t;++c){d[c-e-1]|=(this[c]&f)<<a;d[c-e]=this[c]>>b}if(b>0){d[this.t-e-1]|=(this.s&f)<<a}d.t=this.t-e;d.clamp()}function bnpSubTo(d,f){var e=0,g=0,b=Math.min(d.t,this.t);while(e<b){g+=this[e]-d[e];f[e++]=g&this.DM;g>>=this.DB}if(d.t<this.t){g-=d.s;while(e<this.t){g+=this[e];f[e++]=g&this.DM;g>>=this.DB}g+=this.s}else{g+=this.s;while(e<d.t){g-=d[e];f[e++]=g&this.DM;g>>=this.DB}g-=d.s}f.s=(g<0)?-1:0;if(g<-1){f[e++]=this.DV+g}else{if(g>0){f[e++]=g}}f.t=e;f.clamp()}function bnpMultiplyTo(c,e){var b=this.abs(),f=c.abs();var d=b.t;e.t=d+f.t;while(--d>=0){e[d]=0}for(d=0;d<f.t;++d){e[d+b.t]=b.am(0,f[d],e,d,0,b.t)}e.s=0;e.clamp();if(this.s!=c.s){BigInteger.ZERO.subTo(e,e)}}function bnpSquareTo(d){var a=this.abs();var b=d.t=2*a.t;while(--b>=0){d[b]=0}for(b=0;b<a.t-1;++b){var e=a.am(b,a[b],d,2*b,0,1);if((d[b+a.t]+=a.am(b+1,2*a[b],d,2*b+1,e,a.t-b-1))>=a.DV){d[b+a.t]-=a.DV;d[b+a.t+1]=1}}if(d.t>0){d[d.t-1]+=a.am(b,a[b],d,2*b,0,1)}d.s=0;d.clamp()}function bnpDivRemTo(n,h,g){var w=n.abs();if(w.t<=0){return}var k=this.abs();if(k.t<w.t){if(h!=null){h.fromInt(0)}if(g!=null){this.copyTo(g)}return}if(g==null){g=nbi()}var d=nbi(),a=this.s,l=n.s;var v=this.DB-nbits(w[w.t-1]);if(v>0){w.lShiftTo(v,d);k.lShiftTo(v,g)}else{w.copyTo(d);k.copyTo(g)}var p=d.t;var b=d[p-1];if(b==0){return}var o=b*(1<<this.F1)+((p>1)?d[p-2]>>this.F2:0);var A=this.FV/o,z=(1<<this.F1)/o,x=1<<this.F2;var u=g.t,s=u-p,f=(h==null)?nbi():h;d.dlShiftTo(s,f);if(g.compareTo(f)>=0){g[g.t++]=1;g.subTo(f,g)}BigInteger.ONE.dlShiftTo(p,f);f.subTo(d,d);while(d.t<p){d[d.t++]=0}while(--s>=0){var c=(g[--u]==b)?this.DM:Math.floor(g[u]*A+(g[u-1]+x)*z);if((g[u]+=d.am(0,c,g,s,0,p))<c){d.dlShiftTo(s,f);g.subTo(f,g);while(g[u]<--c){g.subTo(f,g)}}}if(h!=null){g.drShiftTo(p,h);if(a!=l){BigInteger.ZERO.subTo(h,h)}}g.t=p;g.clamp();if(v>0){g.rShiftTo(v,g)}if(a<0){BigInteger.ZERO.subTo(g,g)}}function bnMod(b){var c=nbi();this.abs().divRemTo(b,null,c);if(this.s<0&&c.compareTo(BigInteger.ZERO)>0){b.subTo(c,c)}return c}function Classic(a){this.m=a}function cConvert(a){if(a.s<0||a.compareTo(this.m)>=0){return a.mod(this.m)}else{return a}}function cRevert(a){return a}function cReduce(a){a.divRemTo(this.m,null,a)}function cMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}function cSqrTo(a,b){a.squareTo(b);this.reduce(b)}Classic.prototype.convert=cConvert;Classic.prototype.revert=cRevert;Classic.prototype.reduce=cReduce;Classic.prototype.mulTo=cMulTo;Classic.prototype.sqrTo=cSqrTo;function bnpInvDigit(){if(this.t<1){return 0}var a=this[0];if((a&1)==0){return 0}var b=a&3;b=(b*(2-(a&15)*b))&15;b=(b*(2-(a&255)*b))&255;b=(b*(2-(((a&65535)*b)&65535)))&65535;b=(b*(2-a*b%this.DV))%this.DV;return(b>0)?this.DV-b:-b}function Montgomery(a){this.m=a;this.mp=a.invDigit();this.mpl=this.mp&32767;this.mph=this.mp>>15;this.um=(1<<(a.DB-15))-1;this.mt2=2*a.t}function montConvert(a){var b=nbi();a.abs().dlShiftTo(this.m.t,b);b.divRemTo(this.m,null,b);if(a.s<0&&b.compareTo(BigInteger.ZERO)>0){this.m.subTo(b,b)}return b}function montRevert(a){var b=nbi();a.copyTo(b);this.reduce(b);return b}function montReduce(a){while(a.t<=this.mt2){a[a.t++]=0}for(var c=0;c<this.m.t;++c){var b=a[c]&32767;var d=(b*this.mpl+(((b*this.mph+(a[c]>>15)*this.mpl)&this.um)<<15))&a.DM;b=c+this.m.t;a[b]+=this.m.am(0,d,a,c,0,this.m.t);while(a[b]>=a.DV){a[b]-=a.DV;a[++b]++}}a.clamp();a.drShiftTo(this.m.t,a);if(a.compareTo(this.m)>=0){a.subTo(this.m,a)}}function montSqrTo(a,b){a.squareTo(b);this.reduce(b)}function montMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}Montgomery.prototype.convert=montConvert;Montgomery.prototype.revert=montRevert;Montgomery.prototype.reduce=montReduce;Montgomery.prototype.mulTo=montMulTo;Montgomery.prototype.sqrTo=montSqrTo;function bnpIsEven(){return((this.t>0)?(this[0]&1):this.s)==0}function bnpExp(h,j){if(h>4294967295||h<1){return BigInteger.ONE}var f=nbi(),a=nbi(),d=j.convert(this),c=nbits(h)-1;d.copyTo(f);while(--c>=0){j.sqrTo(f,a);if((h&(1<<c))>0){j.mulTo(a,d,f)}else{var b=f;f=a;a=b}}return j.revert(f)}function bnModPowInt(b,a){var c;if(b<256||a.isEven()){c=new Classic(a)}else{c=new Montgomery(a)}return this.exp(b,c)}BigInteger.prototype.copyTo=bnpCopyTo;BigInteger.prototype.fromInt=bnpFromInt;BigInteger.prototype.fromString=bnpFromString;BigInteger.prototype.clamp=bnpClamp;BigInteger.prototype.dlShiftTo=bnpDLShiftTo;BigInteger.prototype.drShiftTo=bnpDRShiftTo;BigInteger.prototype.lShiftTo=bnpLShiftTo;BigInteger.prototype.rShiftTo=bnpRShiftTo;BigInteger.prototype.subTo=bnpSubTo;BigInteger.prototype.multiplyTo=bnpMultiplyTo;BigInteger.prototype.squareTo=bnpSquareTo;BigInteger.prototype.divRemTo=bnpDivRemTo;BigInteger.prototype.invDigit=bnpInvDigit;BigInteger.prototype.isEven=bnpIsEven;BigInteger.prototype.exp=bnpExp;BigInteger.prototype.toString=bnToString;BigInteger.prototype.negate=bnNegate;BigInteger.prototype.abs=bnAbs;BigInteger.prototype.compareTo=bnCompareTo;BigInteger.prototype.bitLength=bnBitLength;BigInteger.prototype.mod=bnMod;BigInteger.prototype.modPowInt=bnModPowInt;BigInteger.ZERO=nbv(0);BigInteger.ONE=nbv(1);
/*  jsbn2-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function bnClone(){var a=nbi();this.copyTo(a);return a}function bnIntValue(){if(this.s<0){if(this.t==1){return this[0]-this.DV}else{if(this.t==0){return -1}}}else{if(this.t==1){return this[0]}else{if(this.t==0){return 0}}}return((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0]}function bnByteValue(){return(this.t==0)?this.s:(this[0]<<24)>>24}function bnShortValue(){return(this.t==0)?this.s:(this[0]<<16)>>16}function bnpChunkSize(a){return Math.floor(Math.LN2*this.DB/Math.log(a))}function bnSigNum(){if(this.s<0){return -1}else{if(this.t<=0||(this.t==1&&this[0]<=0)){return 0}else{return 1}}}function bnpToRadix(c){if(c==null){c=10}if(this.signum()==0||c<2||c>36){return"0"}var f=this.chunkSize(c);var e=Math.pow(c,f);var i=nbv(e),j=nbi(),h=nbi(),g="";this.divRemTo(i,j,h);while(j.signum()>0){g=(e+h.intValue()).toString(c).substr(1)+g;j.divRemTo(i,j,h)}return h.intValue().toString(c)+g}function bnpFromRadix(m,h){this.fromInt(0);if(h==null){h=10}var f=this.chunkSize(h);var g=Math.pow(h,f),e=false,a=0,l=0;for(var c=0;c<m.length;++c){var k=intAt(m,c);if(k<0){if(m.charAt(c)=="-"&&this.signum()==0){e=true}continue}l=h*l+k;if(++a>=f){this.dMultiply(g);this.dAddOffset(l,0);a=0;l=0}}if(a>0){this.dMultiply(Math.pow(h,a));this.dAddOffset(l,0)}if(e){BigInteger.ZERO.subTo(this,this)}}function bnpFromNumber(f,e,h){if("number"==typeof e){if(f<2){this.fromInt(1)}else{this.fromNumber(f,h);if(!this.testBit(f-1)){this.bitwiseTo(BigInteger.ONE.shiftLeft(f-1),op_or,this)}if(this.isEven()){this.dAddOffset(1,0)}while(!this.isProbablePrime(e)){this.dAddOffset(2,0);if(this.bitLength()>f){this.subTo(BigInteger.ONE.shiftLeft(f-1),this)}}}}else{var d=new Array(),g=f&7;d.length=(f>>3)+1;e.nextBytes(d);if(g>0){d[0]&=((1<<g)-1)}else{d[0]=0}this.fromString(d,256)}}function bnToByteArray(){var b=this.t,c=new Array();c[0]=this.s;var e=this.DB-(b*this.DB)%8,f,a=0;if(b-->0){if(e<this.DB&&(f=this[b]>>e)!=(this.s&this.DM)>>e){c[a++]=f|(this.s<<(this.DB-e))}while(b>=0){if(e<8){f=(this[b]&((1<<e)-1))<<(8-e);f|=this[--b]>>(e+=this.DB-8)}else{f=(this[b]>>(e-=8))&255;if(e<=0){e+=this.DB;--b}}if((f&128)!=0){f|=-256}if(a==0&&(this.s&128)!=(f&128)){++a}if(a>0||f!=this.s){c[a++]=f}}}return c}function bnEquals(b){return(this.compareTo(b)==0)}function bnMin(b){return(this.compareTo(b)<0)?this:b}function bnMax(b){return(this.compareTo(b)>0)?this:b}function bnpBitwiseTo(c,h,e){var d,g,b=Math.min(c.t,this.t);for(d=0;d<b;++d){e[d]=h(this[d],c[d])}if(c.t<this.t){g=c.s&this.DM;for(d=b;d<this.t;++d){e[d]=h(this[d],g)}e.t=this.t}else{g=this.s&this.DM;for(d=b;d<c.t;++d){e[d]=h(g,c[d])}e.t=c.t}e.s=h(this.s,c.s);e.clamp()}function op_and(a,b){return a&b}function bnAnd(b){var c=nbi();this.bitwiseTo(b,op_and,c);return c}function op_or(a,b){return a|b}function bnOr(b){var c=nbi();this.bitwiseTo(b,op_or,c);return c}function op_xor(a,b){return a^b}function bnXor(b){var c=nbi();this.bitwiseTo(b,op_xor,c);return c}function op_andnot(a,b){return a&~b}function bnAndNot(b){var c=nbi();this.bitwiseTo(b,op_andnot,c);return c}function bnNot(){var b=nbi();for(var a=0;a<this.t;++a){b[a]=this.DM&~this[a]}b.t=this.t;b.s=~this.s;return b}function bnShiftLeft(b){var a=nbi();if(b<0){this.rShiftTo(-b,a)}else{this.lShiftTo(b,a)}return a}function bnShiftRight(b){var a=nbi();if(b<0){this.lShiftTo(-b,a)}else{this.rShiftTo(b,a)}return a}function lbit(a){if(a==0){return -1}var b=0;if((a&65535)==0){a>>=16;b+=16}if((a&255)==0){a>>=8;b+=8}if((a&15)==0){a>>=4;b+=4}if((a&3)==0){a>>=2;b+=2}if((a&1)==0){++b}return b}function bnGetLowestSetBit(){for(var a=0;a<this.t;++a){if(this[a]!=0){return a*this.DB+lbit(this[a])}}if(this.s<0){return this.t*this.DB}return -1}function cbit(a){var b=0;while(a!=0){a&=a-1;++b}return b}function bnBitCount(){var c=0,a=this.s&this.DM;for(var b=0;b<this.t;++b){c+=cbit(this[b]^a)}return c}function bnTestBit(b){var a=Math.floor(b/this.DB);if(a>=this.t){return(this.s!=0)}return((this[a]&(1<<(b%this.DB)))!=0)}function bnpChangeBit(c,b){var a=BigInteger.ONE.shiftLeft(c);this.bitwiseTo(a,b,a);return a}function bnSetBit(a){return this.changeBit(a,op_or)}function bnClearBit(a){return this.changeBit(a,op_andnot)}function bnFlipBit(a){return this.changeBit(a,op_xor)}function bnpAddTo(d,f){var e=0,g=0,b=Math.min(d.t,this.t);while(e<b){g+=this[e]+d[e];f[e++]=g&this.DM;g>>=this.DB}if(d.t<this.t){g+=d.s;while(e<this.t){g+=this[e];f[e++]=g&this.DM;g>>=this.DB}g+=this.s}else{g+=this.s;while(e<d.t){g+=d[e];f[e++]=g&this.DM;g>>=this.DB}g+=d.s}f.s=(g<0)?-1:0;if(g>0){f[e++]=g}else{if(g<-1){f[e++]=this.DV+g}}f.t=e;f.clamp()}function bnAdd(b){var c=nbi();this.addTo(b,c);return c}function bnSubtract(b){var c=nbi();this.subTo(b,c);return c}function bnMultiply(b){var c=nbi();this.multiplyTo(b,c);return c}function bnSquare(){var a=nbi();this.squareTo(a);return a}function bnDivide(b){var c=nbi();this.divRemTo(b,c,null);return c}function bnRemainder(b){var c=nbi();this.divRemTo(b,null,c);return c}function bnDivideAndRemainder(b){var d=nbi(),c=nbi();this.divRemTo(b,d,c);return new Array(d,c)}function bnpDMultiply(a){this[this.t]=this.am(0,a-1,this,0,0,this.t);++this.t;this.clamp()}function bnpDAddOffset(b,a){if(b==0){return}while(this.t<=a){this[this.t++]=0}this[a]+=b;while(this[a]>=this.DV){this[a]-=this.DV;if(++a>=this.t){this[this.t++]=0}++this[a]}}function NullExp(){}function nNop(a){return a}function nMulTo(a,c,b){a.multiplyTo(c,b)}function nSqrTo(a,b){a.squareTo(b)}NullExp.prototype.convert=nNop;NullExp.prototype.revert=nNop;NullExp.prototype.mulTo=nMulTo;NullExp.prototype.sqrTo=nSqrTo;function bnPow(a){return this.exp(a,new NullExp())}function bnpMultiplyLowerTo(b,f,e){var d=Math.min(this.t+b.t,f);e.s=0;e.t=d;while(d>0){e[--d]=0}var c;for(c=e.t-this.t;d<c;++d){e[d+this.t]=this.am(0,b[d],e,d,0,this.t)}for(c=Math.min(b.t,f);d<c;++d){this.am(0,b[d],e,d,0,f-d)}e.clamp()}function bnpMultiplyUpperTo(b,e,d){--e;var c=d.t=this.t+b.t-e;d.s=0;while(--c>=0){d[c]=0}for(c=Math.max(e-this.t,0);c<b.t;++c){d[this.t+c-e]=this.am(e-c,b[c],d,0,0,this.t+c-e)}d.clamp();d.drShiftTo(1,d)}function Barrett(a){this.r2=nbi();this.q3=nbi();BigInteger.ONE.dlShiftTo(2*a.t,this.r2);this.mu=this.r2.divide(a);this.m=a}function barrettConvert(a){if(a.s<0||a.t>2*this.m.t){return a.mod(this.m)}else{if(a.compareTo(this.m)<0){return a}else{var b=nbi();a.copyTo(b);this.reduce(b);return b}}}function barrettRevert(a){return a}function barrettReduce(a){a.drShiftTo(this.m.t-1,this.r2);if(a.t>this.m.t+1){a.t=this.m.t+1;a.clamp()}this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);while(a.compareTo(this.r2)<0){a.dAddOffset(1,this.m.t+1)}a.subTo(this.r2,a);while(a.compareTo(this.m)>=0){a.subTo(this.m,a)}}function barrettSqrTo(a,b){a.squareTo(b);this.reduce(b)}function barrettMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}Barrett.prototype.convert=barrettConvert;Barrett.prototype.revert=barrettRevert;Barrett.prototype.reduce=barrettReduce;Barrett.prototype.mulTo=barrettMulTo;Barrett.prototype.sqrTo=barrettSqrTo;function bnModPow(q,f){var o=q.bitLength(),h,b=nbv(1),v;if(o<=0){return b}else{if(o<18){h=1}else{if(o<48){h=3}else{if(o<144){h=4}else{if(o<768){h=5}else{h=6}}}}}if(o<8){v=new Classic(f)}else{if(f.isEven()){v=new Barrett(f)}else{v=new Montgomery(f)}}var p=new Array(),d=3,s=h-1,a=(1<<h)-1;p[1]=v.convert(this);if(h>1){var A=nbi();v.sqrTo(p[1],A);while(d<=a){p[d]=nbi();v.mulTo(A,p[d-2],p[d]);d+=2}}var l=q.t-1,x,u=true,c=nbi(),y;o=nbits(q[l])-1;while(l>=0){if(o>=s){x=(q[l]>>(o-s))&a}else{x=(q[l]&((1<<(o+1))-1))<<(s-o);if(l>0){x|=q[l-1]>>(this.DB+o-s)}}d=h;while((x&1)==0){x>>=1;--d}if((o-=d)<0){o+=this.DB;--l}if(u){p[x].copyTo(b);u=false}else{while(d>1){v.sqrTo(b,c);v.sqrTo(c,b);d-=2}if(d>0){v.sqrTo(b,c)}else{y=b;b=c;c=y}v.mulTo(c,p[x],b)}while(l>=0&&(q[l]&(1<<o))==0){v.sqrTo(b,c);y=b;b=c;c=y;if(--o<0){o=this.DB-1;--l}}}return v.revert(b)}function bnGCD(c){var b=(this.s<0)?this.negate():this.clone();var h=(c.s<0)?c.negate():c.clone();if(b.compareTo(h)<0){var e=b;b=h;h=e}var d=b.getLowestSetBit(),f=h.getLowestSetBit();if(f<0){return b}if(d<f){f=d}if(f>0){b.rShiftTo(f,b);h.rShiftTo(f,h)}while(b.signum()>0){if((d=b.getLowestSetBit())>0){b.rShiftTo(d,b)}if((d=h.getLowestSetBit())>0){h.rShiftTo(d,h)}if(b.compareTo(h)>=0){b.subTo(h,b);b.rShiftTo(1,b)}else{h.subTo(b,h);h.rShiftTo(1,h)}}if(f>0){h.lShiftTo(f,h)}return h}function bnpModInt(e){if(e<=0){return 0}var c=this.DV%e,b=(this.s<0)?e-1:0;if(this.t>0){if(c==0){b=this[0]%e}else{for(var a=this.t-1;a>=0;--a){b=(c*b+this[a])%e}}}return b}function bnModInverse(f){var j=f.isEven();if((this.isEven()&&j)||f.signum()==0){return BigInteger.ZERO}var i=f.clone(),h=this.clone();var g=nbv(1),e=nbv(0),l=nbv(0),k=nbv(1);while(i.signum()!=0){while(i.isEven()){i.rShiftTo(1,i);if(j){if(!g.isEven()||!e.isEven()){g.addTo(this,g);e.subTo(f,e)}g.rShiftTo(1,g)}else{if(!e.isEven()){e.subTo(f,e)}}e.rShiftTo(1,e)}while(h.isEven()){h.rShiftTo(1,h);if(j){if(!l.isEven()||!k.isEven()){l.addTo(this,l);k.subTo(f,k)}l.rShiftTo(1,l)}else{if(!k.isEven()){k.subTo(f,k)}}k.rShiftTo(1,k)}if(i.compareTo(h)>=0){i.subTo(h,i);if(j){g.subTo(l,g)}e.subTo(k,e)}else{h.subTo(i,h);if(j){l.subTo(g,l)}k.subTo(e,k)}}if(h.compareTo(BigInteger.ONE)!=0){return BigInteger.ZERO}if(k.compareTo(f)>=0){return k.subtract(f)}if(k.signum()<0){k.addTo(f,k)}else{return k}if(k.signum()<0){return k.add(f)}else{return k}}var lowprimes=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];var lplim=(1<<26)/lowprimes[lowprimes.length-1];function bnIsProbablePrime(e){var d,b=this.abs();if(b.t==1&&b[0]<=lowprimes[lowprimes.length-1]){for(d=0;d<lowprimes.length;++d){if(b[0]==lowprimes[d]){return true}}return false}if(b.isEven()){return false}d=1;while(d<lowprimes.length){var a=lowprimes[d],c=d+1;while(c<lowprimes.length&&a<lplim){a*=lowprimes[c++]}a=b.modInt(a);while(d<c){if(a%lowprimes[d++]==0){return false}}}return b.millerRabin(e)}function bnpMillerRabin(f){var g=this.subtract(BigInteger.ONE);var c=g.getLowestSetBit();if(c<=0){return false}var h=g.shiftRight(c);f=(f+1)>>1;if(f>lowprimes.length){f=lowprimes.length}var b=nbi();for(var e=0;e<f;++e){b.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);var l=b.modPow(h,this);if(l.compareTo(BigInteger.ONE)!=0&&l.compareTo(g)!=0){var d=1;while(d++<c&&l.compareTo(g)!=0){l=l.modPowInt(2,this);if(l.compareTo(BigInteger.ONE)==0){return false}}if(l.compareTo(g)!=0){return false}}}return true}BigInteger.prototype.chunkSize=bnpChunkSize;BigInteger.prototype.toRadix=bnpToRadix;BigInteger.prototype.fromRadix=bnpFromRadix;BigInteger.prototype.fromNumber=bnpFromNumber;BigInteger.prototype.bitwiseTo=bnpBitwiseTo;BigInteger.prototype.changeBit=bnpChangeBit;BigInteger.prototype.addTo=bnpAddTo;BigInteger.prototype.dMultiply=bnpDMultiply;BigInteger.prototype.dAddOffset=bnpDAddOffset;BigInteger.prototype.multiplyLowerTo=bnpMultiplyLowerTo;BigInteger.prototype.multiplyUpperTo=bnpMultiplyUpperTo;BigInteger.prototype.modInt=bnpModInt;BigInteger.prototype.millerRabin=bnpMillerRabin;BigInteger.prototype.clone=bnClone;BigInteger.prototype.intValue=bnIntValue;BigInteger.prototype.byteValue=bnByteValue;BigInteger.prototype.shortValue=bnShortValue;BigInteger.prototype.signum=bnSigNum;BigInteger.prototype.toByteArray=bnToByteArray;BigInteger.prototype.equals=bnEquals;BigInteger.prototype.min=bnMin;BigInteger.prototype.max=bnMax;BigInteger.prototype.and=bnAnd;BigInteger.prototype.or=bnOr;BigInteger.prototype.xor=bnXor;BigInteger.prototype.andNot=bnAndNot;BigInteger.prototype.not=bnNot;BigInteger.prototype.shiftLeft=bnShiftLeft;BigInteger.prototype.shiftRight=bnShiftRight;BigInteger.prototype.getLowestSetBit=bnGetLowestSetBit;BigInteger.prototype.bitCount=bnBitCount;BigInteger.prototype.testBit=bnTestBit;BigInteger.prototype.setBit=bnSetBit;BigInteger.prototype.clearBit=bnClearBit;BigInteger.prototype.flipBit=bnFlipBit;BigInteger.prototype.add=bnAdd;BigInteger.prototype.subtract=bnSubtract;BigInteger.prototype.multiply=bnMultiply;BigInteger.prototype.divide=bnDivide;BigInteger.prototype.remainder=bnRemainder;BigInteger.prototype.divideAndRemainder=bnDivideAndRemainder;BigInteger.prototype.modPow=bnModPow;BigInteger.prototype.modInverse=bnModInverse;BigInteger.prototype.pow=bnPow;BigInteger.prototype.gcd=bnGCD;BigInteger.prototype.isProbablePrime=bnIsProbablePrime;BigInteger.prototype.square=bnSquare;
/*  rsa-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function parseBigInt(b,a){return new BigInteger(b,a)}function linebrk(c,d){var a="";var b=0;while(b+d<c.length){a+=c.substring(b,b+d)+"\n";b+=d}return a+c.substring(b,c.length)}function byte2Hex(a){if(a<16){return"0"+a.toString(16)}else{return a.toString(16)}}function pkcs1pad2(e,h){if(h<e.length+11){alert("Message too long for RSA");return null}var g=new Array();var d=e.length-1;while(d>=0&&h>0){var f=e.charCodeAt(d--);if(f<128){g[--h]=f}else{if((f>127)&&(f<2048)){g[--h]=(f&63)|128;g[--h]=(f>>6)|192}else{g[--h]=(f&63)|128;g[--h]=((f>>6)&63)|128;g[--h]=(f>>12)|224}}}g[--h]=0;var b=new SecureRandom();var a=new Array();while(h>2){a[0]=0;while(a[0]==0){b.nextBytes(a)}g[--h]=a[0]}g[--h]=2;g[--h]=0;return new BigInteger(g)}function oaep_mgf1_arr(c,a,e){var b="",d=0;while(b.length<a){b+=e(String.fromCharCode.apply(String,c.concat([(d&4278190080)>>24,(d&16711680)>>16,(d&65280)>>8,d&255])));d+=1}return b}var SHA1_SIZE=20;function oaep_pad(l,a,c){if(l.length+2*SHA1_SIZE+2>a){throw"Message too long for RSA"}var h="",d;for(d=0;d<a-l.length-2*SHA1_SIZE-2;d+=1){h+="\x00"}var e=rstr_sha1("")+h+"\x01"+l;var f=new Array(SHA1_SIZE);new SecureRandom().nextBytes(f);var g=oaep_mgf1_arr(f,e.length,c||rstr_sha1);var k=[];for(d=0;d<e.length;d+=1){k[d]=e.charCodeAt(d)^g.charCodeAt(d)}var j=oaep_mgf1_arr(k,f.length,rstr_sha1);var b=[0];for(d=0;d<f.length;d+=1){b[d+1]=f[d]^j.charCodeAt(d)}return new BigInteger(b.concat(k))}function RSAKey(){this.n=null;this.e=0;this.d=null;this.p=null;this.q=null;this.dmp1=null;this.dmq1=null;this.coeff=null}function RSASetPublic(b,a){this.isPublic=true;if(typeof b!=="string"){this.n=b;this.e=a}else{if(b!=null&&a!=null&&b.length>0&&a.length>0){this.n=parseBigInt(b,16);this.e=parseInt(a,16)}else{alert("Invalid RSA public key")}}}function RSADoPublic(a){return a.modPowInt(this.e,this.n)}function RSAEncrypt(d){var a=pkcs1pad2(d,(this.n.bitLength()+7)>>3);if(a==null){return null}var e=this.doPublic(a);if(e==null){return null}var b=e.toString(16);if((b.length&1)==0){return b}else{return"0"+b}}function RSAEncryptOAEP(e,d){var a=oaep_pad(e,(this.n.bitLength()+7)>>3,d);if(a==null){return null}var f=this.doPublic(a);if(f==null){return null}var b=f.toString(16);if((b.length&1)==0){return b}else{return"0"+b}}RSAKey.prototype.doPublic=RSADoPublic;RSAKey.prototype.setPublic=RSASetPublic;RSAKey.prototype.encrypt=RSAEncrypt;RSAKey.prototype.encryptOAEP=RSAEncryptOAEP;RSAKey.prototype.type="RSA";
/*  rsa2-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function pkcs1unpad2(g,j){var a=g.toByteArray();var f=0;while(f<a.length&&a[f]==0){++f}if(a.length-f!=j-1||a[f]!=2){return null}++f;while(a[f]!=0){if(++f>=a.length){return null}}var e="";while(++f<a.length){var h=a[f]&255;if(h<128){e+=String.fromCharCode(h)}else{if((h>191)&&(h<224)){e+=String.fromCharCode(((h&31)<<6)|(a[f+1]&63));++f}else{e+=String.fromCharCode(((h&15)<<12)|((a[f+1]&63)<<6)|(a[f+2]&63));f+=2}}}return e}function oaep_mgf1_str(c,a,e){var b="",d=0;while(b.length<a){b+=e(c+String.fromCharCode.apply(String,[(d&4278190080)>>24,(d&16711680)>>16,(d&65280)>>8,d&255]));d+=1}return b}var SHA1_SIZE=20;function oaep_unpad(l,b,e){l=l.toByteArray();var f;for(f=0;f<l.length;f+=1){l[f]&=255}while(l.length<b){l.unshift(0)}l=String.fromCharCode.apply(String,l);if(l.length<2*SHA1_SIZE+2){throw"Cipher too short"}var c=l.substr(1,SHA1_SIZE);var o=l.substr(SHA1_SIZE+1);var m=oaep_mgf1_str(o,SHA1_SIZE,e||rstr_sha1);var h=[],f;for(f=0;f<c.length;f+=1){h[f]=c.charCodeAt(f)^m.charCodeAt(f)}var j=oaep_mgf1_str(String.fromCharCode.apply(String,h),l.length-SHA1_SIZE,rstr_sha1);var g=[];for(f=0;f<o.length;f+=1){g[f]=o.charCodeAt(f)^j.charCodeAt(f)}g=String.fromCharCode.apply(String,g);if(g.substr(0,SHA1_SIZE)!==rstr_sha1("")){throw"Hash mismatch"}g=g.substr(SHA1_SIZE);var a=g.indexOf("\x01");var k=(a!=-1)?g.substr(0,a).lastIndexOf("\x00"):-1;if(k+1!=a){throw"Malformed data"}return g.substr(a+1)}function RSASetPrivate(c,a,b){this.isPrivate=true;if(typeof c!=="string"){this.n=c;this.e=a;this.d=b}else{if(c!=null&&a!=null&&c.length>0&&a.length>0){this.n=parseBigInt(c,16);this.e=parseInt(a,16);this.d=parseBigInt(b,16)}else{alert("Invalid RSA private key")}}}function RSASetPrivateEx(g,d,e,c,b,a,h,f){this.isPrivate=true;if(g==null){throw"RSASetPrivateEx N == null"}if(d==null){throw"RSASetPrivateEx E == null"}if(g.length==0){throw"RSASetPrivateEx N.length == 0"}if(d.length==0){throw"RSASetPrivateEx E.length == 0"}if(g!=null&&d!=null&&g.length>0&&d.length>0){this.n=parseBigInt(g,16);this.e=parseInt(d,16);this.d=parseBigInt(e,16);this.p=parseBigInt(c,16);this.q=parseBigInt(b,16);this.dmp1=parseBigInt(a,16);this.dmq1=parseBigInt(h,16);this.coeff=parseBigInt(f,16)}else{alert("Invalid RSA private key in RSASetPrivateEx")}}function RSAGenerate(b,i){var a=new SecureRandom();var f=b>>1;this.e=parseInt(i,16);var c=new BigInteger(i,16);for(;;){for(;;){this.p=new BigInteger(b-f,1,a);if(this.p.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE)==0&&this.p.isProbablePrime(10)){break}}for(;;){this.q=new BigInteger(f,1,a);if(this.q.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE)==0&&this.q.isProbablePrime(10)){break}}if(this.p.compareTo(this.q)<=0){var h=this.p;this.p=this.q;this.q=h}var g=this.p.subtract(BigInteger.ONE);var d=this.q.subtract(BigInteger.ONE);var e=g.multiply(d);if(e.gcd(c).compareTo(BigInteger.ONE)==0){this.n=this.p.multiply(this.q);this.d=c.modInverse(e);this.dmp1=this.d.mod(g);this.dmq1=this.d.mod(d);this.coeff=this.q.modInverse(this.p);break}}}function RSADoPrivate(a){if(this.p==null||this.q==null){return a.modPow(this.d,this.n)}var c=a.mod(this.p).modPow(this.dmp1,this.p);var b=a.mod(this.q).modPow(this.dmq1,this.q);while(c.compareTo(b)<0){c=c.add(this.p)}return c.subtract(b).multiply(this.coeff).mod(this.p).multiply(this.q).add(b)}function RSADecrypt(b){var d=parseBigInt(b,16);var a=this.doPrivate(d);if(a==null){return null}return pkcs1unpad2(a,(this.n.bitLength()+7)>>3)}function RSADecryptOAEP(d,b){var e=parseBigInt(d,16);var a=this.doPrivate(e);if(a==null){return null}return oaep_unpad(a,(this.n.bitLength()+7)>>3,b)}RSAKey.prototype.doPrivate=RSADoPrivate;RSAKey.prototype.setPrivate=RSASetPrivate;RSAKey.prototype.setPrivateEx=RSASetPrivateEx;RSAKey.prototype.generate=RSAGenerate;RSAKey.prototype.decrypt=RSADecrypt;RSAKey.prototype.decryptOAEP=RSADecryptOAEP;
/* rsapem-1.1.min.js  */
/*! rsapem-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function _rsapem_pemToBase64(b){var a=b;a=a.replace("-----BEGIN RSA PRIVATE KEY-----","");a=a.replace("-----END RSA PRIVATE KEY-----","");a=a.replace(/[ \n]+/g,"");return a}function _rsapem_getPosArrayOfChildrenFromHex(d){var j=new Array();var k=ASN1HEX.getStartPosOfV_AtObj(d,0);var f=ASN1HEX.getPosOfNextSibling_AtObj(d,k);var h=ASN1HEX.getPosOfNextSibling_AtObj(d,f);var b=ASN1HEX.getPosOfNextSibling_AtObj(d,h);var l=ASN1HEX.getPosOfNextSibling_AtObj(d,b);var e=ASN1HEX.getPosOfNextSibling_AtObj(d,l);var g=ASN1HEX.getPosOfNextSibling_AtObj(d,e);var c=ASN1HEX.getPosOfNextSibling_AtObj(d,g);var i=ASN1HEX.getPosOfNextSibling_AtObj(d,c);j.push(k,f,h,b,l,e,g,c,i);return j}function _rsapem_getHexValueArrayOfChildrenFromHex(i){var o=_rsapem_getPosArrayOfChildrenFromHex(i);var r=ASN1HEX.getHexOfV_AtObj(i,o[0]);var f=ASN1HEX.getHexOfV_AtObj(i,o[1]);var j=ASN1HEX.getHexOfV_AtObj(i,o[2]);var k=ASN1HEX.getHexOfV_AtObj(i,o[3]);var c=ASN1HEX.getHexOfV_AtObj(i,o[4]);var b=ASN1HEX.getHexOfV_AtObj(i,o[5]);var h=ASN1HEX.getHexOfV_AtObj(i,o[6]);var g=ASN1HEX.getHexOfV_AtObj(i,o[7]);var l=ASN1HEX.getHexOfV_AtObj(i,o[8]);var m=new Array();m.push(r,f,j,k,c,b,h,g,l);return m}function _rsapem_readPrivateKeyFromASN1HexString(c){var b=_rsapem_getHexValueArrayOfChildrenFromHex(c);this.setPrivateEx(b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8])}function _rsapem_readPrivateKeyFromPEMString(e){var c=_rsapem_pemToBase64(e);var d=b64tohex(c);var b=_rsapem_getHexValueArrayOfChildrenFromHex(d);this.setPrivateEx(b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8])}RSAKey.prototype.readPrivateKeyFromPEMString=_rsapem_readPrivateKeyFromPEMString;RSAKey.prototype.readPrivateKeyFromASN1HexString=_rsapem_readPrivateKeyFromASN1HexString;
/* rsasign-1.2.min.js  */
/*! rsasign-1.2.7.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var _RE_HEXDECONLY=new RegExp("");_RE_HEXDECONLY.compile("[^0-9a-f]","gi");function _rsasign_getHexPaddedDigestInfoForString(d,e,a){var b=function(f){return KJUR.crypto.Util.hashString(f,a)};var c=b(d);return KJUR.crypto.Util.getPaddedDigestInfoHex(c,a,e)}function _zeroPaddingOfSignature(e,d){var c="";var a=d/4-e.length;for(var b=0;b<a;b++){c=c+"0"}return c+e}function _rsasign_signString(d,a){var b=function(e){return KJUR.crypto.Util.hashString(e,a)};var c=b(d);return this.signWithMessageHash(c,a)}function _rsasign_signWithMessageHash(e,c){var f=KJUR.crypto.Util.getPaddedDigestInfoHex(e,c,this.n.bitLength());var b=parseBigInt(f,16);var d=this.doPrivate(b);var a=d.toString(16);return _zeroPaddingOfSignature(a,this.n.bitLength())}function _rsasign_signStringWithSHA1(a){return _rsasign_signString.call(this,a,"sha1")}function _rsasign_signStringWithSHA256(a){return _rsasign_signString.call(this,a,"sha256")}function pss_mgf1_str(c,a,e){var b="",d=0;while(b.length<a){b+=hextorstr(e(rstrtohex(c+String.fromCharCode.apply(String,[(d&4278190080)>>24,(d&16711680)>>16,(d&65280)>>8,d&255]))));d+=1}return b}function _rsasign_signStringPSS(e,a,d){var c=function(f){return KJUR.crypto.Util.hashHex(f,a)};var b=c(rstrtohex(e));if(d===undefined){d=-1}return this.signWithMessageHashPSS(b,a,d)}function _rsasign_signWithMessageHashPSS(l,a,k){var b=hextorstr(l);var g=b.length;var m=this.n.bitLength()-1;var c=Math.ceil(m/8);var d;var o=function(i){return KJUR.crypto.Util.hashHex(i,a)};if(k===-1||k===undefined){k=g}else{if(k===-2){k=c-g-2}else{if(k<-2){throw"invalid salt length"}}}if(c<(g+k+2)){throw"data too long"}var f="";if(k>0){f=new Array(k);new SecureRandom().nextBytes(f);f=String.fromCharCode.apply(String,f)}var n=hextorstr(o(rstrtohex("\x00\x00\x00\x00\x00\x00\x00\x00"+b+f)));var j=[];for(d=0;d<c-k-g-2;d+=1){j[d]=0}var e=String.fromCharCode.apply(String,j)+"\x01"+f;var h=pss_mgf1_str(n,e.length,o);var q=[];for(d=0;d<e.length;d+=1){q[d]=e.charCodeAt(d)^h.charCodeAt(d)}var p=(65280>>(8*c-m))&255;q[0]&=~p;for(d=0;d<g;d++){q.push(n.charCodeAt(d))}q.push(188);return _zeroPaddingOfSignature(this.doPrivate(new BigInteger(q)).toString(16),this.n.bitLength())}function _rsasign_getDecryptSignatureBI(a,d,c){var b=new RSAKey();b.setPublic(d,c);var e=b.doPublic(a);return e}function _rsasign_getHexDigestInfoFromSig(a,c,b){var e=_rsasign_getDecryptSignatureBI(a,c,b);var d=e.toString(16).replace(/^1f+00/,"");return d}function _rsasign_getAlgNameAndHashFromHexDisgestInfo(f){for(var e in KJUR.crypto.Util.DIGESTINFOHEAD){var d=KJUR.crypto.Util.DIGESTINFOHEAD[e];var b=d.length;if(f.substring(0,b)==d){var c=[e,f.substring(b)];return c}}return[]}function _rsasign_verifySignatureWithArgs(f,b,g,j){var e=_rsasign_getHexDigestInfoFromSig(b,g,j);var h=_rsasign_getAlgNameAndHashFromHexDisgestInfo(e);if(h.length==0){return false}var d=h[0];var i=h[1];var a=function(k){return KJUR.crypto.Util.hashString(k,d)};var c=a(f);return(i==c)}function _rsasign_verifyHexSignatureForMessage(c,b){var d=parseBigInt(c,16);var a=_rsasign_verifySignatureWithArgs(b,d,this.n.toString(16),this.e.toString(16));return a}function _rsasign_verifyString(f,j){j=j.replace(_RE_HEXDECONLY,"");j=j.replace(/[ \n]+/g,"");var b=parseBigInt(j,16);if(b.bitLength()>this.n.bitLength()){return 0}var i=this.doPublic(b);var e=i.toString(16).replace(/^1f+00/,"");var g=_rsasign_getAlgNameAndHashFromHexDisgestInfo(e);if(g.length==0){return false}var d=g[0];var h=g[1];var a=function(k){return KJUR.crypto.Util.hashString(k,d)};var c=a(f);return(h==c)}function _rsasign_verifyWithMessageHash(e,a){a=a.replace(_RE_HEXDECONLY,"");a=a.replace(/[ \n]+/g,"");var b=parseBigInt(a,16);if(b.bitLength()>this.n.bitLength()){return 0}var h=this.doPublic(b);var g=h.toString(16).replace(/^1f+00/,"");var c=_rsasign_getAlgNameAndHashFromHexDisgestInfo(g);if(c.length==0){return false}var d=c[0];var f=c[1];return(f==e)}function _rsasign_verifyStringPSS(c,b,a,f){var e=function(g){return KJUR.crypto.Util.hashHex(g,a)};var d=e(rstrtohex(c));if(f===undefined){f=-1}return this.verifyWithMessageHashPSS(d,b,a,f)}function _rsasign_verifyWithMessageHashPSS(f,s,l,c){var k=new BigInteger(s,16);if(k.bitLength()>this.n.bitLength()){return false}var r=function(i){return KJUR.crypto.Util.hashHex(i,l)};var j=hextorstr(f);var h=j.length;var g=this.n.bitLength()-1;var m=Math.ceil(g/8);var q;if(c===-1||c===undefined){c=h}else{if(c===-2){c=m-h-2}else{if(c<-2){throw"invalid salt length"}}}if(m<(h+c+2)){throw"data too long"}var a=this.doPublic(k).toByteArray();for(q=0;q<a.length;q+=1){a[q]&=255}while(a.length<m){a.unshift(0)}if(a[m-1]!==188){throw"encoded message does not end in 0xbc"}a=String.fromCharCode.apply(String,a);var d=a.substr(0,m-h-1);var e=a.substr(d.length,h);var p=(65280>>(8*m-g))&255;if((d.charCodeAt(0)&p)!==0){throw"bits beyond keysize not zero"}var n=pss_mgf1_str(e,d.length,r);var o=[];for(q=0;q<d.length;q+=1){o[q]=d.charCodeAt(q)^n.charCodeAt(q)}o[0]&=~p;var b=m-h-c-2;for(q=0;q<b;q+=1){if(o[q]!==0){throw"leftmost octets not zero"}}if(o[b]!==1){throw"0x01 marker not found"}return e===hextorstr(r(rstrtohex("\x00\x00\x00\x00\x00\x00\x00\x00"+j+String.fromCharCode.apply(String,o.slice(-c)))))}RSAKey.prototype.signWithMessageHash=_rsasign_signWithMessageHash;RSAKey.prototype.signString=_rsasign_signString;RSAKey.prototype.signStringWithSHA1=_rsasign_signStringWithSHA1;RSAKey.prototype.signStringWithSHA256=_rsasign_signStringWithSHA256;RSAKey.prototype.sign=_rsasign_signString;RSAKey.prototype.signWithSHA1=_rsasign_signStringWithSHA1;RSAKey.prototype.signWithSHA256=_rsasign_signStringWithSHA256;RSAKey.prototype.signWithMessageHashPSS=_rsasign_signWithMessageHashPSS;RSAKey.prototype.signStringPSS=_rsasign_signStringPSS;RSAKey.prototype.signPSS=_rsasign_signStringPSS;RSAKey.SALT_LEN_HLEN=-1;RSAKey.SALT_LEN_MAX=-2;RSAKey.prototype.verifyWithMessageHash=_rsasign_verifyWithMessageHash;RSAKey.prototype.verifyString=_rsasign_verifyString;RSAKey.prototype.verifyHexSignatureForMessage=_rsasign_verifyHexSignatureForMessage;RSAKey.prototype.verify=_rsasign_verifyString;RSAKey.prototype.verifyHexSignatureForByteArrayMessage=_rsasign_verifyHexSignatureForMessage;RSAKey.prototype.verifyWithMessageHashPSS=_rsasign_verifyWithMessageHashPSS;RSAKey.prototype.verifyStringPSS=_rsasign_verifyStringPSS;RSAKey.prototype.verifyPSS=_rsasign_verifyStringPSS;RSAKey.SALT_LEN_RECOVER=-2;
/* asn1hex-1.1.min.js  */
/*! asn1hex-1.1.8.js (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
 var ASN1HEX = new function() {
 };

 /**
  * get byte length for ASN.1 L(length) bytes<br/>
  * @name getByteLengthOfL_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} s hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos string index
  * @return byte length for ASN.1 L(length) bytes
  */
 ASN1HEX.getByteLengthOfL_AtObj = function(s, pos) {
     if (s.substring(pos + 2, pos + 3) != '8') return 1;
     var i = parseInt(s.substring(pos + 3, pos + 4));
     if (i == 0) return -1;             // length octet '80' indefinite length
     if (0 < i && i < 10) return i + 1; // including '8?' octet;
     return -2;                         // malformed format
 };

 /**
  * get hexadecimal string for ASN.1 L(length) bytes<br/>
  * @name getHexOfL_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} s hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos string index
  * @return {String} hexadecimal string for ASN.1 L(length) bytes
  */
 ASN1HEX.getHexOfL_AtObj = function(s, pos) {
     var len = ASN1HEX.getByteLengthOfL_AtObj(s, pos);
     if (len < 1) return '';
     return s.substring(pos + 2, pos + 2 + len * 2);
 };

 /**
  * get integer value of ASN.1 length for ASN.1 data<br/>
  * @name getIntOfL_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} s hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos string index
  * @return ASN.1 L(length) integer value
  */
 /*
  getting ASN.1 length value at the position 'idx' of
  hexa decimal string 's'.
  f('3082025b02...', 0) ... 82025b ... ???
  f('020100', 0) ... 01 ... 1
  f('0203001...', 0) ... 03 ... 3
  f('02818003...', 0) ... 8180 ... 128
  */
 ASN1HEX.getIntOfL_AtObj = function(s, pos) {
     var hLength = ASN1HEX.getHexOfL_AtObj(s, pos);
     if (hLength == '') return -1;
     var bi;
     if (parseInt(hLength.substring(0, 1)) < 8) {
         bi = new BigInteger(hLength, 16);
     } else {
         bi = new BigInteger(hLength.substring(2), 16);
     }
     return bi.intValue();
 };

 /**
  * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
  * @name getStartPosOfV_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} s hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos string index
  */
 ASN1HEX.getStartPosOfV_AtObj = function(s, pos) {
     var l_len = ASN1HEX.getByteLengthOfL_AtObj(s, pos);
     if (l_len < 0) return l_len;
     return pos + (l_len + 1) * 2;
 };

 /**
  * get hexadecimal string of ASN.1 V(value)
  * @name getHexOfV_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} s hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos string index
  * @return {String} hexadecimal string of ASN.1 value.
  */
 ASN1HEX.getHexOfV_AtObj = function(s, pos) {
     var pos1 = ASN1HEX.getStartPosOfV_AtObj(s, pos);
     var len = ASN1HEX.getIntOfL_AtObj(s, pos);
     return s.substring(pos1, pos1 + len * 2);
 };

 /**
  * get hexadecimal string of ASN.1 TLV at<br/>
  * @name getHexOfTLV_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} s hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos string index
  * @return {String} hexadecimal string of ASN.1 TLV.
  * @since asn1hex 1.1
  */
 ASN1HEX.getHexOfTLV_AtObj = function(s, pos) {
     var hT = s.substr(pos, 2);
     var hL = ASN1HEX.getHexOfL_AtObj(s, pos);
     var hV = ASN1HEX.getHexOfV_AtObj(s, pos);
     return hT + hL + hV;
 };

 // ========== sibling methods ================================
 /**
  * get next sibling starting index for ASN.1 object string<br/>
  * @name getPosOfNextSibling_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} s hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos string index
  * @return next sibling starting index for ASN.1 object string
  */
 ASN1HEX.getPosOfNextSibling_AtObj = function(s, pos) {
     var pos1 = ASN1HEX.getStartPosOfV_AtObj(s, pos);
     var len = ASN1HEX.getIntOfL_AtObj(s, pos);
     return pos1 + len * 2;
 };

 // ========== children methods ===============================
 /**
  * get array of string indexes of child ASN.1 objects<br/>
  * @name getPosArrayOfChildren_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} h hexadecimal string of ASN.1 DER encoded data
  * @param {Number} pos start string index of ASN.1 object
  * @return {Array of Number} array of indexes for childen of ASN.1 objects
  * @description
  * This method returns array of integers for a concatination of ASN.1 objects
  * in a ASN.1 value. As for BITSTRING, one byte of unusedbits is skipped.
  * As for other ASN.1 simple types such as INTEGER, OCTET STRING or PRINTABLE STRING,
  * it returns a array of a string index of its ASN.1 value.<br/>
  * NOTE: Since asn1hex 1.1.7 of jsrsasign 6.1.2, Encapsulated BitString is supported.
  * @example
  * ASN1HEX.getPosArrayOfChildren_AtObj("0203012345", 0) &rArr; [4] // INTEGER 012345
  * ASN1HEX.getPosArrayOfChildren_AtObj("1303616161", 0) &rArr; [4] // PrintableString aaa
  * ASN1HEX.getPosArrayOfChildren_AtObj("030300ffff", 0) &rArr; [6] // BITSTRING ffff (unusedbits=00a)
  * ASN1HEX.getPosArrayOfChildren_AtObj("3006020104020105", 0) &rArr; [4, 10] // SEQUENCE(INT4,INT5)
  */
 ASN1HEX.getPosArrayOfChildren_AtObj = function(h, pos) {
     var a = new Array();
     var p0 = ASN1HEX.getStartPosOfV_AtObj(h, pos);
     if (h.substr(pos, 2) == "03") {
 	a.push(p0 + 2); // BITSTRING value without unusedbits
     } else {
 	a.push(p0);
     }

     var len = ASN1HEX.getIntOfL_AtObj(h, pos);
     var p = p0;
     var k = 0;
     while (1) {
         var pNext = ASN1HEX.getPosOfNextSibling_AtObj(h, p);
         if (pNext == null || (pNext - p0  >= (len * 2))) break;
         if (k >= 200) break;

         a.push(pNext);
         p = pNext;

         k++;
     }

     return a;
 };

 /**
  * get string index of nth child object of ASN.1 object refered by h, idx<br/>
  * @name getNthChildIndex_AtObj
  * @memberOf ASN1HEX
  * @function
  * @param {String} h hexadecimal string of ASN.1 DER encoded data
  * @param {Number} idx start string index of ASN.1 object
  * @param {Number} nth for child
  * @return {Number} string index of nth child.
  * @since 1.1
  */
 ASN1HEX.getNthChildIndex_AtObj = function(h, idx, nth) {
     var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, idx);
     return a[nth];
 };

 // ========== decendant methods ==============================
 /**
  * get string index of nth child object of ASN.1 object refered by h, idx<br/>
  * @name getDecendantIndexByNthList
  * @memberOf ASN1HEX
  * @function
  * @param {String} h hexadecimal string of ASN.1 DER encoded data
  * @param {Number} currentIndex start string index of ASN.1 object
  * @param {Array of Number} nthList array list of nth
  * @return {Number} string index refered by nthList
  * @since 1.1
  * @example
  * The "nthList" is a index list of structured ASN.1 object
  * reference. Here is a sample structure and "nthList"s which
  * refers each objects.
  *
  * SQUENCE               -
  *   SEQUENCE            - [0]
  *     IA5STRING 000     - [0, 0]
  *     UTF8STRING 001    - [0, 1]
  *   SET                 - [1]
  *     IA5STRING 010     - [1, 0]
  *     UTF8STRING 011    - [1, 1]
  */
 ASN1HEX.getDecendantIndexByNthList = function(h, currentIndex, nthList) {
     if (nthList.length == 0) {
         return currentIndex;
     }
     var firstNth = nthList.shift();
     var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, currentIndex);
     return ASN1HEX.getDecendantIndexByNthList(h, a[firstNth], nthList);
 };

 /**
  * get hexadecimal string of ASN.1 TLV refered by current index and nth index list.
  * @name getDecendantHexTLVByNthList
  * @memberOf ASN1HEX
  * @function
  * @param {String} h hexadecimal string of ASN.1 DER encoded data
  * @param {Number} currentIndex start string index of ASN.1 object
  * @param {Array of Number} nthList array list of nth
  * @return {Number} hexadecimal string of ASN.1 TLV refered by nthList
  * @since 1.1
  */
 ASN1HEX.getDecendantHexTLVByNthList = function(h, currentIndex, nthList) {
     var idx = ASN1HEX.getDecendantIndexByNthList(h, currentIndex, nthList);
     return ASN1HEX.getHexOfTLV_AtObj(h, idx);
 };

 /**
  * get hexadecimal string of ASN.1 V refered by current index and nth index list.
  * @name getDecendantHexVByNthList
  * @memberOf ASN1HEX
  * @function
  * @param {String} h hexadecimal string of ASN.1 DER encoded data
  * @param {Number} currentIndex start string index of ASN.1 object
  * @param {Array of Number} nthList array list of nth
  * @return {Number} hexadecimal string of ASN.1 V refered by nthList
  * @since 1.1
  */
 ASN1HEX.getDecendantHexVByNthList = function(h, currentIndex, nthList) {
     var idx = ASN1HEX.getDecendantIndexByNthList(h, currentIndex, nthList);
     return ASN1HEX.getHexOfV_AtObj(h, idx);
 };

 /**
  * get ASN.1 value by nthList<br/>
  * @name getVbyList
  * @memberOf ASN1HEX
  * @function
  * @param {String} h hexadecimal string of ASN.1 structure
  * @param {Integer} currentIndex string index to start searching in hexadecimal string "h"
  * @param {Array} nthList array of nth list index
  * @param {String} checkingTag (OPTIONAL) string of expected ASN.1 tag for nthList
  * @description
  * This static method is to get a ASN.1 value which specified "nthList" position
  * with checking expected tag "checkingTag".
  * @since asn1hex 1.1.4
  */
 ASN1HEX.getVbyList = function(h, currentIndex, nthList, checkingTag) {
     var idx = ASN1HEX.getDecendantIndexByNthList(h, currentIndex, nthList);
     if (idx === undefined) {
         throw "can't find nthList object";
     }
     if (checkingTag !== undefined) {
         if (h.substr(idx, 2) != checkingTag) {
             throw "checking tag doesn't match: " +
                 h.substr(idx,2) + "!=" + checkingTag;
         }
     }
     return ASN1HEX.getHexOfV_AtObj(h, idx);
 };

 /**
  * get OID string from hexadecimal encoded value<br/>
  * @name hextooidstr
  * @memberOf ASN1HEX
  * @function
  * @param {String} hex hexadecmal string of ASN.1 DER encoded OID value
  * @return {String} OID string (ex. '1.2.3.4.567')
  * @since asn1hex 1.1.5
  */
 ASN1HEX.hextooidstr = function(hex) {
     var zeroPadding = function(s, len) {
         if (s.length >= len) return s;
         return new Array(len - s.length + 1).join('0') + s;
     };

     var a = [];

     // a[0], a[1]
     var hex0 = hex.substr(0, 2);
     var i0 = parseInt(hex0, 16);
     a[0] = new String(Math.floor(i0 / 40));
     a[1] = new String(i0 % 40);

     // a[2]..a[n]
    var hex1 = hex.substr(2);
     var b = [];
     for (var i = 0; i < hex1.length / 2; i++) {
     b.push(parseInt(hex1.substr(i * 2, 2), 16));
     }
     var c = [];
     var cbin = "";
     for (var i = 0; i < b.length; i++) {
         if (b[i] & 0x80) {
             cbin = cbin + zeroPadding((b[i] & 0x7f).toString(2), 7);
         } else {
             cbin = cbin + zeroPadding((b[i] & 0x7f).toString(2), 7);
             c.push(new String(parseInt(cbin, 2)));
             cbin = "";
         }
     }

     var s = a.join(".");
     if (c.length > 0) s = s + "." + c.join(".");
     return s;
 };

 /**
  * get string of simple ASN.1 dump from hexadecimal ASN.1 data<br/>
  * @name dump
  * @memberOf ASN1HEX
  * @function
  * @param {Object} hexOrObj hexadecmal string of ASN.1 data or ASN1Object object
  * @param {Array} flags associative array of flags for dump (OPTION)
  * @param {Number} idx string index for starting dump (OPTION)
  * @param {String} indent indent string (OPTION)
  * @return {String} string of simple ASN.1 dump
  * @since jsrsasign 4.8.3 asn1hex 1.1.6
  * @description
  * This method will get an ASN.1 dump from
  * hexadecmal string of ASN.1 DER encoded data.
  * Here are features:
  * <ul>
  * <li>ommit long hexadecimal string</li>
  * <li>dump encapsulated OCTET STRING (good for X.509v3 extensions)</li>
  * <li>structured/primitive context specific tag support (i.e. [0], [3] ...)</li>
  * <li>automatic decode for implicit primitive context specific tag
  * (good for X.509v3 extension value)
  *   <ul>
  *   <li>if hex starts '68747470'(i.e. http) it is decoded as utf8 encoded string.</li>
  *   <li>if it is in 'subjectAltName' extension value and is '[2]'(dNSName) tag
  *   value will be encoded as utf8 string</li>
  *   <li>otherwise it shows as hexadecimal string</li>
  *   </ul>
  * </li>
  * </ul>
  * NOTE1: Argument {@link KJUR.asn1.ASN1Object} object is supported since
  * jsrsasign 6.2.4 asn1hex 1.0.8
  * @example
  * // 1) ASN.1 INTEGER
  * ASN1HEX.dump('0203012345')
  * &darr;
  * INTEGER 012345
  *
  * // 2) ASN.1 Object Identifier
  * ASN1HEX.dump('06052b0e03021a')
  * &darr;
  * ObjectIdentifier sha1 (1 3 14 3 2 26)
  *
  * // 3) ASN.1 SEQUENCE
  * ASN1HEX.dump('3006020101020102')
  * &darr;
  * SEQUENCE
  *   INTEGER 01
  *   INTEGER 02
  *
  * // 4) ASN.1 SEQUENCE since jsrsasign 6.2.4
  * o = KJUR.asn1.ASN1Util.newObject({seq: [{int: 1}, {int: 2}]});
  * ASN1HEX.dump(o)
  * &darr;
  * SEQUENCE
  *   INTEGER 01
  *   INTEGER 02
  * // 5) ASN.1 DUMP FOR X.509 CERTIFICATE
  * ASN1HEX.dump(X509.pemToHex(certPEM))
  * &darr;
  * SEQUENCE
  *   SEQUENCE
  *     [0]
  *       INTEGER 02
  *     INTEGER 0c009310d206dbe337553580118ddc87
  *     SEQUENCE
  *       ObjectIdentifier SHA256withRSA (1 2 840 113549 1 1 11)
  *       NULL
  *     SEQUENCE
  *       SET
  *         SEQUENCE
  *           ObjectIdentifier countryName (2 5 4 6)
  *           PrintableString 'US'
  *             :
  */
 ASN1HEX.dump = function(hexOrObj, flags, idx, indent) {
     var hex = hexOrObj;
     if (hexOrObj instanceof KJUR.asn1.ASN1Object)
 	hex = hexOrObj.getEncodedHex();

     var _skipLongHex = function(hex, limitNumOctet) {
 	if (hex.length <= limitNumOctet * 2) {
 	    return hex;
 	} else {
 	    var s = hex.substr(0, limitNumOctet) +
 		    "..(total " + hex.length / 2 + "bytes).." +
 		    hex.substr(hex.length - limitNumOctet, limitNumOctet);
 	    return s;
 	};
     };

     if (flags === undefined) flags = { "ommit_long_octet": 32 };
     if (idx === undefined) idx = 0;
     if (indent === undefined) indent = "";
     var skipLongHex = flags.ommit_long_octet;

     if (hex.substr(idx, 2) == "01") {
 	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
 	if (v == "00") {
 	    return indent + "BOOLEAN FALSE\n";
 	} else {
 	    return indent + "BOOLEAN TRUE\n";
 	}
     }
     if (hex.substr(idx, 2) == "02") {
 	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
 	return indent + "INTEGER " + _skipLongHex(v, skipLongHex) + "\n";
     }
     if (hex.substr(idx, 2) == "03") {
 	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
 	return indent + "BITSTRING " + _skipLongHex(v, skipLongHex) + "\n";
     }
     if (hex.substr(idx, 2) == "04") {
 	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
 	if (ASN1HEX.isASN1HEX(v)) {
 	    var s = indent + "OCTETSTRING, encapsulates\n";
 	    s = s + ASN1HEX.dump(v, flags, 0, indent + "  ");
 	    return s;
 	} else {
 	    return indent + "OCTETSTRING " + _skipLongHex(v, skipLongHex) + "\n";
 	}
     }
     if (hex.substr(idx, 2) == "05") {
 	return indent + "NULL\n";
     }
     if (hex.substr(idx, 2) == "06") {
 	var hV = ASN1HEX.getHexOfV_AtObj(hex, idx);
         var oidDot = KJUR.asn1.ASN1Util.oidHexToInt(hV);
         var oidName = KJUR.asn1.x509.OID.oid2name(oidDot);
 	var oidSpc = oidDot.replace(/\./g, ' ');
         if (oidName != '') {
   	    return indent + "ObjectIdentifier " + oidName + " (" + oidSpc + ")\n";
 	} else {
   	    return indent + "ObjectIdentifier (" + oidSpc + ")\n";
 	}
     }
     if (hex.substr(idx, 2) == "0c") {
 	return indent + "UTF8String '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
     }
     if (hex.substr(idx, 2) == "13") {
 	return indent + "PrintableString '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
     }
     if (hex.substr(idx, 2) == "14") {
 	return indent + "TeletexString '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
     }
     if (hex.substr(idx, 2) == "16") {
 	return indent + "IA5String '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
     }
     if (hex.substr(idx, 2) == "17") {
 	return indent + "UTCTime " + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "\n";
     }
     if (hex.substr(idx, 2) == "18") {
 	return indent + "GeneralizedTime " + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "\n";
     }
     if (hex.substr(idx, 2) == "30") {
 	if (hex.substr(idx, 4) == "3000") {
 	    return indent + "SEQUENCE {}\n";
 	}

 	var s = indent + "SEQUENCE\n";
 	var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx);

 	var flagsTemp = flags;

 	if ((aIdx.length == 2 || aIdx.length == 3) &&
 	    hex.substr(aIdx[0], 2) == "06" &&
 	    hex.substr(aIdx[aIdx.length - 1], 2) == "04") { // supposed X.509v3 extension
 	    var oidHex = ASN1HEX.getHexOfV_AtObj(hex, aIdx[0]);
 	    var oidDot = KJUR.asn1.ASN1Util.oidHexToInt(oidHex);
 	    var oidName = KJUR.asn1.x509.OID.oid2name(oidDot);

 	    var flagsClone = JSON.parse(JSON.stringify(flags));
 	    flagsClone.x509ExtName = oidName;
 	    flagsTemp = flagsClone;
 	}

 	for (var i = 0; i < aIdx.length; i++) {
 	    s = s + ASN1HEX.dump(hex, flagsTemp, aIdx[i], indent + "  ");
 	}
 	return s;
     }
     if (hex.substr(idx, 2) == "31") {
 	var s = indent + "SET\n";
 	var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx);
 	for (var i = 0; i < aIdx.length; i++) {
 	    s = s + ASN1HEX.dump(hex, flags, aIdx[i], indent + "  ");
 	}
 	return s;
     }
     var tag = parseInt(hex.substr(idx, 2), 16);
     if ((tag & 128) != 0) { // context specific
 	var tagNumber = tag & 31;
 	if ((tag & 32) != 0) { // structured tag
 	    var s = indent + "[" + tagNumber + "]\n";
 	    var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx);
 	    for (var i = 0; i < aIdx.length; i++) {
 		s = s + ASN1HEX.dump(hex, flags, aIdx[i], indent + "  ");
 	    }
 	    return s;
 	} else { // primitive tag
 	    var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
 	    if (v.substr(0, 8) == "68747470") { // http
 		v = hextoutf8(v);
 	    }
 	    if (flags.x509ExtName === "subjectAltName" &&
 		tagNumber == 2) {
 		v = hextoutf8(v);
 	    }

 	    var s = indent + "[" + tagNumber + "] " + v + "\n";
 	    return s;
 	}
     }
     return indent + "UNKNOWN(" + hex.substr(idx, 2) + ") " +
 	   ASN1HEX.getHexOfV_AtObj(hex, idx) + "\n";
 };

 /**
  * check wheather the string is ASN.1 hexadecimal string or not
  * @name isASN1HEX
  * @memberOf ASN1HEX
  * @function
  * @param {String} hex string to check whether it is hexadecmal string for ASN.1 DER or not
  * @return {Boolean} true if it is hexadecimal string of ASN.1 data otherwise false
  * @since jsrsasign 4.8.3 asn1hex 1.1.6
  * @description
  * This method checks wheather the argument 'hex' is a hexadecimal string of
  * ASN.1 data or not.
  * @example
  * ASN1HEX.isASN1HEX('0203012345') &rarr; true // PROPER ASN.1 INTEGER
  * ASN1HEX.isASN1HEX('0203012345ff') &rarr; false // TOO LONG VALUE
  * ASN1HEX.isASN1HEX('02030123') &rarr; false // TOO SHORT VALUE
  * ASN1HEX.isASN1HEX('fa3bcd') &rarr; false // WRONG FOR ASN.1
  */
 ASN1HEX.isASN1HEX = function(hex) {
     if (hex.length % 2 == 1) return false;

     var intL = ASN1HEX.getIntOfL_AtObj(hex, 0);
     var tV = hex.substr(0, 2);
     var lV = ASN1HEX.getHexOfL_AtObj(hex, 0);
     var hVLength = hex.length - tV.length - lV.length;
     if (hVLength == intL * 2) return true;

     return false;
 };
/* x509-1.1.min.js  */
/*! x509-1.1.10.js (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function X509() { this.subjectPublicKeyRSA = null; this.subjectPublicKeyRSA_hN = null; this.subjectPublicKeyRSA_hE = null; this.hex = null; this.getSerialNumberHex = function() { return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]); }; this.getSignatureAlgorithmField = function() { var sigAlgOidHex = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 2, 0]); var sigAlgOidInt = KJUR.asn1.ASN1Util.oidHexToInt(sigAlgOidHex); var sigAlgName = KJUR.asn1.x509.OID.oid2name(sigAlgOidInt); return sigAlgName; }; this.getIssuerHex = function() { return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]); }; this.getIssuerString = function() { return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3])); }; this.getSubjectHex = function() { return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]); }; this.getSubjectString = function() { return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5])); }; this.getNotBefore = function() { var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]); s = s.replace(/(..)/g, "%$1"); s = decodeURIComponent(s); return s; }; this.getNotAfter = function() { var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]); s = s.replace(/(..)/g, "%$1"); s = decodeURIComponent(s); return s; }; this.readCertPEM = function(sCertPEM) { var hCert = X509.pemToHex(sCertPEM); var a = X509.getPublicKeyHexArrayFromCertHex(hCert); var rsa = new RSAKey(); rsa.setPublic(a[0], a[1]); this.subjectPublicKeyRSA = rsa; this.subjectPublicKeyRSA_hN = a[0]; this.subjectPublicKeyRSA_hE = a[1]; this.hex = hCert; }; this.readCertPEMWithoutRSAInit = function(sCertPEM) { var hCert = X509.pemToHex(sCertPEM); var a = X509.getPublicKeyHexArrayFromCertHex(hCert); if (typeof this.subjectPublicKeyRSA.setPublic === "function") { this.subjectPublicKeyRSA.setPublic(a[0], a[1]); } this.subjectPublicKeyRSA_hN = a[0]; this.subjectPublicKeyRSA_hE = a[1]; this.hex = hCert; }; this.getInfo = function() { var s = "Basic Fields\n"; s += " serial number: " + this.getSerialNumberHex() + "\n"; s += " signature algorithm: " + this.getSignatureAlgorithmField() + "\n"; s += " issuer: " + this.getIssuerString() + "\n"; s += " notBefore: " + this.getNotBefore() + "\n"; s += " notAfter: " + this.getNotAfter() + "\n"; s += " subject: " + this.getSubjectString() + "\n"; s += " subject public key info: " + "\n"; var pSPKI = X509.getSubjectPublicKeyInfoPosFromCertHex(this.hex); var hSPKI = ASN1HEX.getHexOfTLV_AtObj(this.hex, pSPKI); var keyObj = KEYUTIL.getKey(hSPKI, null, "pkcs8pub"); if (keyObj instanceof RSAKey) { s += " key algorithm: RSA\n"; s += " n=" + keyObj.n.toString(16).substr(0, 16) + "...\n"; s += " e=" + keyObj.e.toString(16) + "\n"; } s += "X509v3 Extensions:\n"; var aExt = X509.getV3ExtInfoListOfCertHex(this.hex); for (var i = 0; i < aExt.length; i++) { var info = aExt[i]; var extName = KJUR.asn1.x509.OID.oid2name(info["oid"]); if (extName === '') extName = info["oid"]; var critical = ''; if (info["critical"] === true) critical = "CRITICAL"; s += " " + extName + " " + critical + ":\n"; if (extName === "basicConstraints") { var bc = X509.getExtBasicConstraints(this.hex); if (bc.cA === undefined) { s += " {}\n"; } else { s += " cA=true"; if (bc.pathLen !== undefined) s += ", pathLen=" + bc.pathLen; s += "\n"; } } else if (extName === "keyUsage") { s += " " + X509.getExtKeyUsageString(this.hex) + "\n"; } else if (extName === "subjectKeyIdentifier") { s += " " + X509.getExtSubjectKeyIdentifier(this.hex) + "\n"; } else if (extName === "authorityKeyIdentifier") { var akid = X509.getExtAuthorityKeyIdentifier(this.hex); if (akid.kid !== undefined) s += " kid=" + akid.kid + "\n"; } else if (extName === "extKeyUsage") { var eku = X509.getExtExtKeyUsageName(this.hex); s += " " + eku.join(", ") + "\n"; } else if (extName === "subjectAltName") { var san = X509.getExtSubjectAltName(this.hex); s += " " + san.join(", ") + "\n"; } else if (extName === "cRLDistributionPoints") { var cdp = X509.getExtCRLDistributionPointsURI(this.hex); s += " " + cdp + "\n"; } else if (extName === "authorityInfoAccess") { var aia = X509.getExtAIAInfo(this.hex); if (aia.ocsp !== undefined) s += " ocsp: " + aia.ocsp.join(",") + "\n"; if (aia.caissuer !== undefined) s += " caissuer: " + aia.caissuer.join(",") + "\n"; } } s += "signature algorithm: " + X509.getSignatureAlgorithmName(this.hex) + "\n"; s += "signature: " + X509.getSignatureValueHex(this.hex).substr(0, 16) + "...\n"; return s; }; }; X509.pemToBase64 = function(sCertPEM) { var s = sCertPEM; s = s.replace("-----BEGIN CERTIFICATE-----", ""); s = s.replace("-----END CERTIFICATE-----", ""); s = s.replace(/[ \n]+/g, ""); return s; }; X509.pemToHex = function(sCertPEM) { var b64Cert = X509.pemToBase64(sCertPEM); var hCert = b64tohex(b64Cert); return hCert; }; X509.getSubjectPublicKeyPosFromCertHex = function(hCert) { var pInfo = X509.getSubjectPublicKeyInfoPosFromCertHex(hCert); if (pInfo == -1) return -1; var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo); if (a.length != 2) return -1; var pBitString = a[1]; if (hCert.substring(pBitString, pBitString + 2) != '03') return -1; var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString); if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1; return pBitStringV + 2; }; X509.getSubjectPublicKeyInfoPosFromCertHex = function(hCert) { var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0); var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert); if (a.length < 1) return -1; if (hCert.substring(a[0], a[0] + 10) == "a003020102") { if (a.length < 6) return -1; return a[6]; } else { if (a.length < 5) return -1; return a[5]; } }; X509.getPublicKeyHexArrayFromCertHex = function(hCert) { var p = X509.getSubjectPublicKeyPosFromCertHex(hCert); var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); if (a.length != 2) return []; var hN = ASN1HEX.getHexOfV_AtObj(hCert, a[0]); var hE = ASN1HEX.getHexOfV_AtObj(hCert, a[1]); if (hN != null && hE != null) { return [hN, hE]; } else { return []; } }; X509.getHexTbsCertificateFromCert = function(hCert) { var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0); return pTbsCert; }; X509.getPublicKeyHexArrayFromCertPEM = function(sCertPEM) { var hCert = X509.pemToHex(sCertPEM); var a = X509.getPublicKeyHexArrayFromCertHex(hCert); return a; }; X509.hex2dn = function(hex, idx) { if (idx === undefined) idx = 0; if (hex.substr(idx, 2) !== "30") throw "malformed DN"; var a = new Array(); var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx); for (var i = 0; i < aIdx.length; i++) { a.push(X509.hex2rdn(hex, aIdx[i])); } a = a.map(function(s) { return s.replace("/", "\\/"); }); return "/" + a.join("/"); }; X509.hex2rdn = function(hex, idx) { if (idx === undefined) idx = 0; if (hex.substr(idx, 2) !== "31") throw "malformed RDN"; var a = new Array(); var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx); for (var i = 0; i < aIdx.length; i++) { a.push(X509.hex2attrTypeValue(hex, aIdx[i])); } a = a.map(function(s) { return s.replace("+", "\\+"); }); return a.join("+"); }; X509.hex2attrTypeValue = function(hex, idx) { if (idx === undefined) idx = 0; if (hex.substr(idx, 2) !== "30") throw "malformed attribute type and value"; var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx); if (aIdx.length !== 2 || hex.substr(aIdx[0], 2) !== "06") "malformed attribute type and value"; var oidHex = ASN1HEX.getHexOfV_AtObj(hex, aIdx[0]); var oidInt = KJUR.asn1.ASN1Util.oidHexToInt(oidHex); var atype = KJUR.asn1.x509.OID.oid2atype(oidInt); var hV = ASN1HEX.getHexOfV_AtObj(hex, aIdx[1]); var rawV = hextorstr(hV); return atype + "=" + rawV; }; X509.getPublicKeyFromCertPEM = function(sCertPEM) { var info = X509.getPublicKeyInfoPropOfCertPEM(sCertPEM); if (info.algoid == "2a864886f70d010101") { var aRSA = KEYUTIL.parsePublicRawRSAKeyHex(info.keyhex); var key = new RSAKey(); key.setPublic(aRSA.n, aRSA.e); return key; } else if (info.algoid == "2a8648ce3d0201") { var curveName = KJUR.crypto.OID.oidhex2name[info.algparam]; var key = new KJUR.crypto.ECDSA({'curve': curveName, 'info': info.keyhex}); key.setPublicKeyHex(info.keyhex); return key; } else if (info.algoid == "2a8648ce380401") { var p = ASN1HEX.getVbyList(info.algparam, 0, [0], "02"); var q = ASN1HEX.getVbyList(info.algparam, 0, [1], "02"); var g = ASN1HEX.getVbyList(info.algparam, 0, [2], "02"); var y = ASN1HEX.getHexOfV_AtObj(info.keyhex, 0); y = y.substr(2); var key = new KJUR.crypto.DSA(); key.setPublic(new BigInteger(p, 16), new BigInteger(q, 16), new BigInteger(g, 16), new BigInteger(y, 16)); return key; } else { throw "unsupported key"; } }; X509.getPublicKeyInfoPropOfCertPEM = function(sCertPEM) { var result = {}; result.algparam = null; var hCert = X509.pemToHex(sCertPEM); var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); if (a1.length != 3) throw "malformed X.509 certificate PEM (code:001)"; if (hCert.substr(a1[0], 2) != "30") throw "malformed X.509 certificate PEM (code:002)"; var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); var idx_spi = 6; if (hCert.substr(a2[0], 2) !== "a0") idx_spi = 5; if (a2.length < idx_spi + 1) throw "malformed X.509 certificate PEM (code:003)"; var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[idx_spi]); if (a3.length != 2) throw "malformed X.509 certificate PEM (code:004)"; var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]); if (a4.length != 2) throw "malformed X.509 certificate PEM (code:005)"; result.algoid = ASN1HEX.getHexOfV_AtObj(hCert, a4[0]); if (hCert.substr(a4[1], 2) == "06") { result.algparam = ASN1HEX.getHexOfV_AtObj(hCert, a4[1]); } else if (hCert.substr(a4[1], 2) == "30") { result.algparam = ASN1HEX.getHexOfTLV_AtObj(hCert, a4[1]); } if (hCert.substr(a3[1], 2) != "03") throw "malformed X.509 certificate PEM (code:006)"; var unusedBitAndKeyHex = ASN1HEX.getHexOfV_AtObj(hCert, a3[1]); result.keyhex = unusedBitAndKeyHex.substr(2); return result; }; X509.getPublicKeyInfoPosOfCertHEX = function(hCert) { var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); if (a1.length != 3) throw "malformed X.509 certificate PEM (code:001)"; if (hCert.substr(a1[0], 2) != "30") throw "malformed X.509 certificate PEM (code:002)"; var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); if (a2.length < 7) throw "malformed X.509 certificate PEM (code:003)"; return a2[6]; }; X509.getV3ExtInfoListOfCertHex = function(hCert) { var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); if (a1.length != 3) throw "malformed X.509 certificate PEM (code:001)"; if (hCert.substr(a1[0], 2) != "30") throw "malformed X.509 certificate PEM (code:002)"; var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); if (a2.length < 8) throw "malformed X.509 certificate PEM (code:003)"; if (hCert.substr(a2[7], 2) != "a3") throw "malformed X.509 certificate PEM (code:004)"; var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[7]); if (a3.length != 1) throw "malformed X.509 certificate PEM (code:005)"; if (hCert.substr(a3[0], 2) != "30") throw "malformed X.509 certificate PEM (code:006)"; var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]); var numExt = a4.length; var aInfo = new Array(numExt); for (var i = 0; i < numExt; i++) { aInfo[i] = X509.getV3ExtItemInfo_AtObj(hCert, a4[i]); } return aInfo; }; X509.getV3ExtItemInfo_AtObj = function(hCert, pos) { var info = {}; info.posTLV = pos; var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos); if (a.length != 2 && a.length != 3) throw "malformed X.509v3 Ext (code:001)"; if (hCert.substr(a[0], 2) != "06") throw "malformed X.509v3 Ext (code:002)"; var valueHex = ASN1HEX.getHexOfV_AtObj(hCert, a[0]); info.oid = ASN1HEX.hextooidstr(valueHex); info.critical = false; if (a.length == 3) info.critical = true; var posExtV = a[a.length - 1]; if (hCert.substr(posExtV, 2) != "04") throw "malformed X.509v3 Ext (code:003)"; info.posV = ASN1HEX.getStartPosOfV_AtObj(hCert, posExtV); return info; }; X509.getHexOfTLV_V3ExtValue = function(hCert, oidOrName) { var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName); if (pos == -1) return null; return ASN1HEX.getHexOfTLV_AtObj(hCert, pos); }; X509.getHexOfV_V3ExtValue = function(hCert, oidOrName) { var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName); if (pos == -1) return null; return ASN1HEX.getHexOfV_AtObj(hCert, pos); }; X509.getPosOfTLV_V3ExtValue = function(hCert, oidOrName) { var oid = oidOrName; if (! oidOrName.match(/^[0-9.]+$/)) oid = KJUR.asn1.x509.OID.name2oid(oidOrName); if (oid == '') return -1; var infoList = X509.getV3ExtInfoListOfCertHex(hCert); for (var i = 0; i < infoList.length; i++) { var info = infoList[i]; if (info.oid == oid) return info.posV; } return -1; }; X509.getExtBasicConstraints = function(hCert) { var hBC = X509.getHexOfV_V3ExtValue(hCert, "basicConstraints"); if (hBC === null) return null; if (hBC === '') return {}; if (hBC === '0101ff') return { "cA": true }; if (hBC.substr(0, 8) === '0101ff02') { var pathLexHex = ASN1HEX.getHexOfV_AtObj(hBC, 6); var pathLen = parseInt(pathLexHex, 16); return { "cA": true, "pathLen": pathLen }; } throw "unknown error"; }; X509.KEYUSAGE_NAME = [ "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" ]; X509.getExtKeyUsageBin = function(hCert) { var hKeyUsage = X509.getHexOfV_V3ExtValue(hCert, "keyUsage"); if (hKeyUsage == '') return ''; if (hKeyUsage.length % 2 != 0 || hKeyUsage.length <= 2) throw "malformed key usage value"; var unusedBits = parseInt(hKeyUsage.substr(0, 2)); var bKeyUsage = parseInt(hKeyUsage.substr(2), 16).toString(2); return bKeyUsage.substr(0, bKeyUsage.length - unusedBits); }; X509.getExtKeyUsageString = function(hCert) { var bKeyUsage = X509.getExtKeyUsageBin(hCert); var a = new Array(); for (var i = 0; i < bKeyUsage.length; i++) { if (bKeyUsage.substr(i, 1) == "1") a.push(X509.KEYUSAGE_NAME[i]); } return a.join(","); }; X509.getExtSubjectKeyIdentifier = function(hCert) { var hSKID = X509.getHexOfV_V3ExtValue(hCert, "subjectKeyIdentifier"); return hSKID; }; X509.getExtAuthorityKeyIdentifier = function(hCert) { var result = {}; var hAKID = X509.getHexOfTLV_V3ExtValue(hCert, "authorityKeyIdentifier"); if (hAKID === null) return null; var a = ASN1HEX.getPosArrayOfChildren_AtObj(hAKID, 0); for (var i = 0; i < a.length; i++) { if (hAKID.substr(a[i], 2) === "80") result.kid = ASN1HEX.getHexOfV_AtObj(hAKID, a[i]); } return result; }; X509.getExtExtKeyUsageName = function(hCert) { var result = new Array(); var h = X509.getHexOfTLV_V3ExtValue(hCert, "extKeyUsage"); if (h === null) return null; var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); for (var i = 0; i < a.length; i++) { var hex = ASN1HEX.getHexOfV_AtObj(h, a[i]); var oid = KJUR.asn1.ASN1Util.oidHexToInt(hex); var name = KJUR.asn1.x509.OID.oid2name(oid); result.push(name); } return result; }; X509.getExtSubjectAltName = function(hCert) { var result = new Array(); var h = X509.getHexOfTLV_V3ExtValue(hCert, "subjectAltName"); var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); for (var i = 0; i < a.length; i++) { if (h.substr(a[i], 2) === "82") { var fqdn = hextoutf8(ASN1HEX.getHexOfV_AtObj(h, a[i])); result.push(fqdn); } } return result; }; X509.getExtCRLDistributionPointsURI = function(hCert) { var result = new Array(); var h = X509.getHexOfTLV_V3ExtValue(hCert, "cRLDistributionPoints"); var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); for (var i = 0; i < a.length; i++) { var hDP = ASN1HEX.getHexOfTLV_AtObj(h, a[i]); var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hDP, 0); for (var j = 0; j < a1.length; j++) { if (hDP.substr(a1[j], 2) === "a0") { var hDPN = ASN1HEX.getHexOfV_AtObj(hDP, a1[j]); if (hDPN.substr(0, 2) === "a0") { var hFullName = ASN1HEX.getHexOfV_AtObj(hDPN, 0); if (hFullName.substr(0, 2) === "86") { var hURI = ASN1HEX.getHexOfV_AtObj(hFullName, 0); var uri = hextoutf8(hURI); result.push(uri); } } } } } return result; }; X509.getExtAIAInfo = function(hCert) { var result = {}; result.ocsp = []; result.caissuer = []; var pos1 = X509.getPosOfTLV_V3ExtValue(hCert, "authorityInfoAccess"); if (pos1 == -1) return null; if (hCert.substr(pos1, 2) != "30") throw "malformed AIA Extn Value"; var posAccDescList = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos1); for (var i = 0; i < posAccDescList.length; i++) { var p = posAccDescList[i]; var posAccDescChild = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); if (posAccDescChild.length != 2) throw "malformed AccessDescription of AIA Extn"; var pOID = posAccDescChild[0]; var pName = posAccDescChild[1]; if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073001") { if (hCert.substr(pName, 2) == "86") { result.ocsp.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName))); } } if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073002") { if (hCert.substr(pName, 2) == "86") { result.caissuer.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName))); } } } return result; }; X509.getSignatureAlgorithmName = function(hCert) { var sigAlgOidHex = ASN1HEX.getDecendantHexVByNthList(hCert, 0, [1, 0]); var sigAlgOidInt = KJUR.asn1.ASN1Util.oidHexToInt(sigAlgOidHex); var sigAlgName = KJUR.asn1.x509.OID.oid2name(sigAlgOidInt); return sigAlgName; }; X509.getSignatureValueHex = function(hCert) { var h = ASN1HEX.getDecendantHexVByNthList(hCert, 0, [2]); if (h.substr(0, 2) !== "00") throw "can't get signature value"; return h.substr(2); }; X509.getSerialNumberHex = function(hCert) { return ASN1HEX.getDecendantHexVByNthList(hCert, 0, [0, 1]); };
/* crypto-1.1.min.js  */
/*! crypto-1.1.11.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
 if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
 if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

 KJUR.crypto.Util = new function() {
     this.DIGESTINFOHEAD = {
 	'sha1':      "3021300906052b0e03021a05000414",
         'sha224':    "302d300d06096086480165030402040500041c",
 	'sha256':    "3031300d060960864801650304020105000420",
 	'sha384':    "3041300d060960864801650304020205000430",
 	'sha512':    "3051300d060960864801650304020305000440",
 	'md2':       "3020300c06082a864886f70d020205000410",
 	'md5':       "3020300c06082a864886f70d020505000410",
 	'ripemd160': "3021300906052b2403020105000414",
     };

     this.DEFAULTPROVIDER = {
 	'md5':			'cryptojs',
 	'sha1':			'cryptojs',
 	'sha224':		'cryptojs',
 	'sha256':		'cryptojs',
 	'sha384':		'cryptojs',
 	'sha512':		'cryptojs',
 	'ripemd160':		'cryptojs',
 	'hmacmd5':		'cryptojs',
 	'hmacsha1':		'cryptojs',
 	'hmacsha224':		'cryptojs',
 	'hmacsha256':		'cryptojs',
 	'hmacsha384':		'cryptojs',
 	'hmacsha512':		'cryptojs',
 	'hmacripemd160':	'cryptojs',

 	'MD5withRSA':		'cryptojs/jsrsa',
 	'SHA1withRSA':		'cryptojs/jsrsa',
 	'SHA224withRSA':	'cryptojs/jsrsa',
 	'SHA256withRSA':	'cryptojs/jsrsa',
 	'SHA384withRSA':	'cryptojs/jsrsa',
 	'SHA512withRSA':	'cryptojs/jsrsa',
 	'RIPEMD160withRSA':	'cryptojs/jsrsa',

 	'MD5withECDSA':		'cryptojs/jsrsa',
 	'SHA1withECDSA':	'cryptojs/jsrsa',
 	'SHA224withECDSA':	'cryptojs/jsrsa',
 	'SHA256withECDSA':	'cryptojs/jsrsa',
 	'SHA384withECDSA':	'cryptojs/jsrsa',
 	'SHA512withECDSA':	'cryptojs/jsrsa',
 	'RIPEMD160withECDSA':	'cryptojs/jsrsa',

 	'SHA1withDSA':		'cryptojs/jsrsa',
 	'SHA224withDSA':	'cryptojs/jsrsa',
 	'SHA256withDSA':	'cryptojs/jsrsa',

 	'MD5withRSAandMGF1':		'cryptojs/jsrsa',
 	'SHA1withRSAandMGF1':		'cryptojs/jsrsa',
 	'SHA224withRSAandMGF1':		'cryptojs/jsrsa',
 	'SHA256withRSAandMGF1':		'cryptojs/jsrsa',
 	'SHA384withRSAandMGF1':		'cryptojs/jsrsa',
 	'SHA512withRSAandMGF1':		'cryptojs/jsrsa',
 	'RIPEMD160withRSAandMGF1':	'cryptojs/jsrsa',
     };

     this.CRYPTOJSMESSAGEDIGESTNAME = {
 	'md5':		CryptoJS.algo.MD5,
 	'sha1':		CryptoJS.algo.SHA1,
 	'sha224':	CryptoJS.algo.SHA224,
 	'sha256':	CryptoJS.algo.SHA256,
 	'sha384':	CryptoJS.algo.SHA384,
 	'sha512':	CryptoJS.algo.SHA512,
 	'ripemd160':	CryptoJS.algo.RIPEMD160
     };

     this.getDigestInfoHex = function(hHash, alg) {
 	if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
 	    throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
 	return this.DIGESTINFOHEAD[alg] + hHash;
     };

     this.getPaddedDigestInfoHex = function(hHash, alg, keySize) {
 	var hDigestInfo = this.getDigestInfoHex(hHash, alg);
 	var pmStrLen = keySize / 4; // minimum PM length

 	if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
 	    throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

 	var hHead = "0001";
 	var hTail = "00" + hDigestInfo;
 	var hMid = "";
 	var fLen = pmStrLen - hHead.length - hTail.length;
 	for (var i = 0; i < fLen; i += 2) {
 	    hMid += "ff";
 	}
 	var hPaddedMessage = hHead + hMid + hTail;
 	return hPaddedMessage;
     };

     /**
      * get hexadecimal hash of string with specified algorithm
      * @name hashString
      * @memberOf KJUR.crypto.Util
      * @function
      * @param {String} s input string to be hashed
      * @param {String} alg hash algorithm name
      * @return {String} hexadecimal string of hash value
      * @since 1.1.1
      */
     this.hashString = function(s, alg) {
         var md = new KJUR.crypto.MessageDigest({'alg': alg});
         return md.digestString(s);
     };

     /**
      * get hexadecimal hash of hexadecimal string with specified algorithm
      * @name hashHex
      * @memberOf KJUR.crypto.Util
      * @function
      * @param {String} sHex input hexadecimal string to be hashed
      * @param {String} alg hash algorithm name
      * @return {String} hexadecimal string of hash value
      * @since 1.1.1
      */
     this.hashHex = function(sHex, alg) {
         var md = new KJUR.crypto.MessageDigest({'alg': alg});
         return md.digestHex(sHex);
     };

     /**
      * get hexadecimal SHA1 hash of string
      * @name sha1
      * @memberOf KJUR.crypto.Util
      * @function
      * @param {String} s input string to be hashed
      * @return {String} hexadecimal string of hash value
      * @since 1.0.3
      */
     this.sha1 = function(s) {
         var md = new KJUR.crypto.MessageDigest({'alg':'sha1', 'prov':'cryptojs'});
         return md.digestString(s);
     };

     /**
      * get hexadecimal SHA256 hash of string
      * @name sha256
      * @memberOf KJUR.crypto.Util
      * @function
      * @param {String} s input string to be hashed
      * @return {String} hexadecimal string of hash value
      * @since 1.0.3
      */
     this.sha256 = function(s) {
         var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
         return md.digestString(s);
     };

     this.sha256Hex = function(s) {
         var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
         return md.digestHex(s);
     };

     /**
      * get hexadecimal SHA512 hash of string
      * @name sha512
      * @memberOf KJUR.crypto.Util
      * @function
      * @param {String} s input string to be hashed
      * @return {String} hexadecimal string of hash value
      * @since 1.0.3
      */
     this.sha512 = function(s) {
         var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
         return md.digestString(s);
     };

     this.sha512Hex = function(s) {
         var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
         return md.digestHex(s);
     };

 };

 /**
  * get hexadecimal MD5 hash of string
  * @name md5
  * @memberOf KJUR.crypto.Util
  * @function
  * @param {String} s input string to be hashed
  * @return {String} hexadecimal string of hash value
  * @since 1.0.3
  * @example
  * Util.md5('aaa') &rarr; 47bce5c74f589f4867dbd57e9ca9f808
  */
 KJUR.crypto.Util.md5 = function(s) {
     var md = new KJUR.crypto.MessageDigest({'alg':'md5', 'prov':'cryptojs'});
     return md.digestString(s);
 };

 /**
  * get hexadecimal RIPEMD160 hash of string
  * @name ripemd160
  * @memberOf KJUR.crypto.Util
  * @function
  * @param {String} s input string to be hashed
  * @return {String} hexadecimal string of hash value
  * @since 1.0.3
  * @example
  * KJUR.crypto.Util.ripemd160("aaa") &rarr; 08889bd7b151aa174c21f33f59147fa65381edea
  */
 KJUR.crypto.Util.ripemd160 = function(s) {
     var md = new KJUR.crypto.MessageDigest({'alg':'ripemd160', 'prov':'cryptojs'});
     return md.digestString(s);
 };

 // @since jsrsasign 7.0.0 crypto 1.1.11
 KJUR.crypto.Util.SECURERANDOMGEN = new SecureRandom();

 /**
  * get hexadecimal string of random value from with specified byte length<br/>
  * @name getRandomHexOfNbytes
  * @memberOf KJUR.crypto.Util
  * @function
  * @param {Integer} n length of bytes of random
  * @return {String} hexadecimal string of random
  * @since jsrsasign 7.0.0 crypto 1.1.11
  * @example
  * KJUR.crypto.Util.getRandomHexOfNbytes(3) &rarr; "6314af", "000000" or "001fb4"
  * KJUR.crypto.Util.getRandomHexOfNbytes(128) &rarr; "8fbc..." in 1024bits
  */
 KJUR.crypto.Util.getRandomHexOfNbytes = function(n) {
     var ba = new Array(n);
     KJUR.crypto.Util.SECURERANDOMGEN.nextBytes(ba);
     return BAtohex(ba);
 };

 KJUR.crypto.Util.getRandomBigIntegerOfNbytes = function(n) {
     return new BigInteger(KJUR.crypto.Util.getRandomHexOfNbytes(n), 16);
 };

 KJUR.crypto.Util.getRandomHexOfNbits = function(n) {
     var n_remainder = n % 8;
     var n_quotient = (n - n_remainder) / 8;
     var ba = new Array(n_quotient + 1);
     KJUR.crypto.Util.SECURERANDOMGEN.nextBytes(ba);
     ba[0] = (((255 << n_remainder) & 255) ^ 255) & ba[0];
     return BAtohex(ba);
 };

 /**
  * get BigInteger object of random value from with specified bit length<br/>
  * @name getRandomBigIntegerOfNbits
  * @memberOf KJUR.crypto.Util
  * @function
  * @param {Integer} n length of bits of random
  * @return {BigInteger} BigInteger object of specified random value
  * @since jsrsasign 7.0.0 crypto 1.1.11
  * @example
  * KJUR.crypto.Util.getRandomBigIntegerOfNbits(24) &rarr; 6314af of BigInteger
  * KJUR.crypto.Util.getRandomBigIntegerOfNbits(1024) &rarr; 8fbc... of BigInteger
  */
 KJUR.crypto.Util.getRandomBigIntegerOfNbits = function(n) {
     return new BigInteger(KJUR.crypto.Util.getRandomHexOfNbits(n), 16);
 };

 KJUR.crypto.Util.getRandomBigIntegerZeroToMax = function(biMax) {
     var bitLenMax = biMax.bitLength();
     while (1) {
 	var biRand = KJUR.crypto.Util.getRandomBigIntegerOfNbits(bitLenMax);
 	if (biMax.compareTo(biRand) != -1) return biRand;
     }
 };

 KJUR.crypto.Util.getRandomBigIntegerMinToMax = function(biMin, biMax) {
     var flagCompare = biMin.compareTo(biMax);
     if (flagCompare == 1) throw "biMin is greater than biMax";
     if (flagCompare == 0) return biMin;

     var biDiff = biMax.subtract(biMin);
     var biRand = KJUR.crypto.Util.getRandomBigIntegerZeroToMax(biDiff);
     return biRand.add(biMin);
 };


 KJUR.crypto.MessageDigest = function(params) {
     var md = null;
     var algName = null;
     var provName = null;

     this.setAlgAndProvider = function(alg, prov) {
 	alg = KJUR.crypto.MessageDigest.getCanonicalAlgName(alg);

 	if (alg !== null && prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];

 	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(alg) != -1 &&
 	    prov == 'cryptojs') {
 	    try {
 		this.md = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[alg].create();
 	    } catch (ex) {
 		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
 	    }
 	    this.updateString = function(str) {
 		this.md.update(str);
 	    };
 	    this.updateHex = function(hex) {
 		var wHex = CryptoJS.enc.Hex.parse(hex);
 		this.md.update(wHex);
 	    };
 	    this.digest = function() {
 		var hash = this.md.finalize();
 		return hash.toString(CryptoJS.enc.Hex);
 	    };
 	    this.digestString = function(str) {
 		this.updateString(str);
 		return this.digest();
 	    };
 	    this.digestHex = function(hex) {
 		this.updateHex(hex);
 		return this.digest();
 	    };
 	}
 	if (':sha256:'.indexOf(alg) != -1 &&
 	    prov == 'sjcl') {
 	    try {
 		this.md = new sjcl.hash.sha256();
 	    } catch (ex) {
 		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
 	    }
 	    this.updateString = function(str) {
 		this.md.update(str);
 	    };
 	    this.updateHex = function(hex) {
 		var baHex = sjcl.codec.hex.toBits(hex);
 		this.md.update(baHex);
 	    };
 	    this.digest = function() {
 		var hash = this.md.finalize();
 		return sjcl.codec.hex.fromBits(hash);
 	    };
 	    this.digestString = function(str) {
 		this.updateString(str);
 		return this.digest();
 	    };
 	    this.digestHex = function(hex) {
 		this.updateHex(hex);
 		return this.digest();
 	    };
 	}
     };

     this.updateString = function(str) {
 	throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
     };

     this.updateHex = function(hex) {
 	throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
     };

     this.digest = function() {
 	throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
     };

     this.digestString = function(str) {
 	throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
     };

     this.digestHex = function(hex) {
 	throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
     };

     if (params !== undefined) {
 	if (params['alg'] !== undefined) {
 	    this.algName = params['alg'];
 	    if (params['prov'] === undefined)
 		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
 	    this.setAlgAndProvider(this.algName, this.provName);
 	}
     }
 };

 KJUR.crypto.MessageDigest.getCanonicalAlgName = function(alg) {
     if (typeof alg === "string") {
 	alg = alg.toLowerCase();
 	alg = alg.replace(/-/, '');
     }
     return alg;
 };

 KJUR.crypto.MessageDigest.getHashLength = function(alg) {
     var MD = KJUR.crypto.MessageDigest
     var alg2 = MD.getCanonicalAlgName(alg);
     if (MD.HASHLENGTH[alg2] === undefined)
 	throw "not supported algorithm: " + alg;
     return MD.HASHLENGTH[alg2];
 };

 KJUR.crypto.MessageDigest.HASHLENGTH = {
     'md5':		16,
     'sha1':		20,
     'sha224':		28,
     'sha256':		32,
     'sha384':		48,
     'sha512':		64,
     'ripemd160':	20
 };


 KJUR.crypto.Mac = function(params) {
     var mac = null;
     var pass = null;
     var algName = null;
     var provName = null;
     var algProv = null;

     this.setAlgAndProvider = function(alg, prov) {
 	alg = alg.toLowerCase();

 	if (alg == null) alg = "hmacsha1";

 	alg = alg.toLowerCase();
         if (alg.substr(0, 4) != "hmac") {
 	    throw "setAlgAndProvider unsupported HMAC alg: " + alg;
 	}

 	if (prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];
 	this.algProv = alg + "/" + prov;

 	var hashAlg = alg.substr(4);

 	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(hashAlg) != -1 &&
 	    prov == 'cryptojs') {
 	    try {
 		var mdObj = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[hashAlg];
 		this.mac = CryptoJS.algo.HMAC.create(mdObj, this.pass);
 	    } catch (ex) {
 		throw "setAlgAndProvider hash alg set fail hashAlg=" + hashAlg + "/" + ex;
 	    }
 	    this.updateString = function(str) {
 		this.mac.update(str);
 	    };
 	    this.updateHex = function(hex) {
 		var wHex = CryptoJS.enc.Hex.parse(hex);
 		this.mac.update(wHex);
 	    };
 	    this.doFinal = function() {
 		var hash = this.mac.finalize();
 		return hash.toString(CryptoJS.enc.Hex);
 	    };
 	    this.doFinalString = function(str) {
 		this.updateString(str);
 		return this.doFinal();
 	    };
 	    this.doFinalHex = function(hex) {
 		this.updateHex(hex);
 		return this.doFinal();
 	    };
 	}
     };

     this.updateString = function(str) {
 	throw "updateString(str) not supported for this alg/prov: " + this.algProv;
     };

     this.updateHex = function(hex) {
 	throw "updateHex(hex) not supported for this alg/prov: " + this.algProv;
     };

     this.doFinal = function() {
 	throw "digest() not supported for this alg/prov: " + this.algProv;
     };

     this.doFinalString = function(str) {
 	throw "digestString(str) not supported for this alg/prov: " + this.algProv;
     };

     this.doFinalHex = function(hex) {
 	throw "digestHex(hex) not supported for this alg/prov: " + this.algProv;
     };

     this.setPassword = function(pass) {

 	if (typeof pass == 'string') {
 	    var hPass = pass;
 	    if (pass.length % 2 == 1 || ! pass.match(/^[0-9A-Fa-f]+$/)) {
 		hPass = rstrtohex(pass);
 	    }
 	    this.pass = CryptoJS.enc.Hex.parse(hPass);
 	    return;
 	}

 	if (typeof pass != 'object')
 	    throw "KJUR.crypto.Mac unsupported password type: " + pass;

 	var hPass = null;
 	if (pass.hex  !== undefined) {
 	    if (pass.hex.length % 2 != 0 || ! pass.hex.match(/^[0-9A-Fa-f]+$/))
 		throw "Mac: wrong hex password: " + pass.hex;
 	    hPass = pass.hex;
 	}
 	if (pass.utf8 !== undefined) hPass = utf8tohex(pass.utf8);
 	if (pass.rstr !== undefined) hPass = rstrtohex(pass.rstr);
 	if (pass.b64  !== undefined) hPass = b64tohex(pass.b64);
 	if (pass.b64u !== undefined) hPass = b64utohex(pass.b64u);

 	if (hPass == null)
 	    throw "KJUR.crypto.Mac unsupported password type: " + pass;

 	this.pass = CryptoJS.enc.Hex.parse(hPass);
     };

     if (params !== undefined) {
 	if (params.pass !== undefined) {
 	    this.setPassword(params.pass);
 	}
 	if (params.alg !== undefined) {
 	    this.algName = params.alg;
 	    if (params['prov'] === undefined)
 		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
 	    this.setAlgAndProvider(this.algName, this.provName);
 	}
     }
 };

 KJUR.crypto.Signature = function(params) {
     var prvKey = null;
     var pubKey = null;

     var md = null;
     var sig = null;
     var algName = null;
     var provName = null;
     var algProvName = null;
     var mdAlgName = null;
     var pubkeyAlgName = null;
     var state = null;
     var pssSaltLen = -1;
     var initParams = null;

     var sHashHex = null;
     var hDigestInfo = null;
     var hPaddedDigestInfo = null;
     var hSign = null;

     this._setAlgNames = function() {
     var matchResult = this.algName.match(/^(.+)with(.+)$/);
 	if (matchResult) {
 	    this.mdAlgName = matchResult[1].toLowerCase();
 	    this.pubkeyAlgName = matchResult[2].toLowerCase();
 	}
     };

     this._zeroPaddingOfSignature = function(hex, bitLength) {
 	var s = "";
 	var nZero = bitLength / 4 - hex.length;
 	for (var i = 0; i < nZero; i++) {
 	    s = s + "0";
 	}
 	return s + hex;
     };

     /**
      * set signature algorithm and provider
      * @name setAlgAndProvider
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {String} alg signature algorithm name
      * @param {String} prov provider name
      * @description
      * @example
      * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
      */
     this.setAlgAndProvider = function(alg, prov) {
 	this._setAlgNames();
 	if (prov != 'cryptojs/jsrsa')
 	    throw "provider not supported: " + prov;

 	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(this.mdAlgName) != -1) {
 	    try {
 		this.md = new KJUR.crypto.MessageDigest({'alg':this.mdAlgName});
 	    } catch (ex) {
 		throw "setAlgAndProvider hash alg set fail alg=" +
                       this.mdAlgName + "/" + ex;
 	    }

 	    this.init = function(keyparam, pass) {
 		var keyObj = null;
 		try {
 		    if (pass === undefined) {
 			keyObj = KEYUTIL.getKey(keyparam);
 		    } else {
 			keyObj = KEYUTIL.getKey(keyparam, pass);
 		    }
 		} catch (ex) {
 		    throw "init failed:" + ex;
 		}

 		if (keyObj.isPrivate === true) {
 		    this.prvKey = keyObj;
 		    this.state = "SIGN";
 		} else if (keyObj.isPublic === true) {
 		    this.pubKey = keyObj;
 		    this.state = "VERIFY";
 		} else {
 		    throw "init failed.:" + keyObj;
 		}
 	    };

 	    this.initSign = function(params) {
 		if (typeof params['ecprvhex'] == 'string' &&
                     typeof params['eccurvename'] == 'string') {
 		    this.ecprvhex = params['ecprvhex'];
 		    this.eccurvename = params['eccurvename'];
 		} else {
 		    this.prvKey = params;
 		}
 		this.state = "SIGN";
 	    };

 	    this.initVerifyByPublicKey = function(params) {
 		if (typeof params['ecpubhex'] == 'string' &&
 		    typeof params['eccurvename'] == 'string') {
 		    this.ecpubhex = params['ecpubhex'];
 		    this.eccurvename = params['eccurvename'];
 		} else if (params instanceof KJUR.crypto.ECDSA) {
 		    this.pubKey = params;
 		} else if (params instanceof RSAKey) {
 		    this.pubKey = params;
 		}
 		this.state = "VERIFY";
 	    };

 	    this.initVerifyByCertificatePEM = function(certPEM) {
 		var x509 = new X509();
 		x509.readCertPEM(certPEM);
 		this.pubKey = x509.subjectPublicKeyRSA;
 		this.state = "VERIFY";
 	    };

 	    this.updateString = function(str) {
 		this.md.updateString(str);
 	    };

 	    this.updateHex = function(hex) {
 		this.md.updateHex(hex);
 	    };

 	    this.sign = function() {
 		this.sHashHex = this.md.digest();
 		if (typeof this.ecprvhex != "undefined" &&
 		    typeof this.eccurvename != "undefined") {
 		    var ec = new KJUR.crypto.ECDSA({'curve': this.eccurvename});
 		    this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
 		} else if (this.prvKey instanceof RSAKey &&
 		           this.pubkeyAlgName == "rsaandmgf1") {
 		    this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex,
 								    this.mdAlgName,
 								    this.pssSaltLen);
 		} else if (this.prvKey instanceof RSAKey &&
 			   this.pubkeyAlgName == "rsa") {
 		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex,
 								 this.mdAlgName);
 		} else if (this.prvKey instanceof KJUR.crypto.ECDSA) {
 		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
 		} else if (this.prvKey instanceof KJUR.crypto.DSA) {
 		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
 		} else {
 		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
 		}
 		return this.hSign;
 	    };
 	    this.signString = function(str) {
 		this.updateString(str);
 		return this.sign();
 	    };
 	    this.signHex = function(hex) {
 		this.updateHex(hex);
 		return this.sign();
 	    };
 	    this.verify = function(hSigVal) {
 	        this.sHashHex = this.md.digest();
 		if (typeof this.ecpubhex != "undefined" &&
 		    typeof this.eccurvename != "undefined") {
 		    var ec = new KJUR.crypto.ECDSA({curve: this.eccurvename});
 		    return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
 		} else if (this.pubKey instanceof RSAKey &&
 			   this.pubkeyAlgName == "rsaandmgf1") {
 		    return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, hSigVal,
 								this.mdAlgName,
 								this.pssSaltLen);
 		} else if (this.pubKey instanceof RSAKey &&
 			   this.pubkeyAlgName == "rsa") {
 		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
 		} else if (this.pubKey instanceof KJUR.crypto.ECDSA) {
 		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
 		} else if (this.pubKey instanceof KJUR.crypto.DSA) {
 		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
 		} else {
 		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
 		}
 	    };
 	}
     };

     /**
      * Initialize this object for signing or verifying depends on key
      * @name init
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {Object} key specifying public or private key as plain/encrypted PKCS#5/8 PEM file, certificate PEM or {@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA} object
      * @param {String} pass (OPTION) passcode for encrypted private key
      * @since crypto 1.1.3
      * @description
      * This method is very useful initialize method for Signature class since
      * you just specify key then this method will automatically initialize it
      * using {@link KEYUTIL.getKey} method.
      * As for 'key',  following argument type are supported:
      * <h5>signing</h5>
      * <ul>
      * <li>PEM formatted PKCS#8 encrypted RSA/ECDSA private key concluding "BEGIN ENCRYPTED PRIVATE KEY"</li>
      * <li>PEM formatted PKCS#5 encrypted RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" and ",ENCRYPTED"</li>
      * <li>PEM formatted PKCS#8 plain RSA/ECDSA private key concluding "BEGIN PRIVATE KEY"</li>
      * <li>PEM formatted PKCS#5 plain RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" without ",ENCRYPTED"</li>
      * <li>RSAKey object of private key</li>
      * <li>KJUR.crypto.ECDSA object of private key</li>
      * <li>KJUR.crypto.DSA object of private key</li>
      * </ul>
      * <h5>verification</h5>
      * <ul>
      * <li>PEM formatted PKCS#8 RSA/EC/DSA public key concluding "BEGIN PUBLIC KEY"</li>
      * <li>PEM formatted X.509 certificate with RSA/EC/DSA public key concluding
      *     "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE" or "BEGIN TRUSTED CERTIFICATE".</li>
      * <li>RSAKey object of public key</li>
      * <li>KJUR.crypto.ECDSA object of public key</li>
      * <li>KJUR.crypto.DSA object of public key</li>
      * </ul>
      * @example
      * sig.init(sCertPEM)
      */
     this.init = function(key, pass) {
 	throw "init(key, pass) not supported for this alg:prov=" +
 	      this.algProvName;
     };

     /**
      * Initialize this object for verifying with a public key
      * @name initVerifyByPublicKey
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {Object} param RSAKey object of public key or associative array for ECDSA
      * @since 1.0.2
      * @deprecated from crypto 1.1.5. please use init() method instead.
      * @description
      * Public key information will be provided as 'param' parameter and the value will be
      * following:
      * <ul>
      * <li>{@link RSAKey} object for RSA verification</li>
      * <li>associative array for ECDSA verification
      *     (ex. <code>{'ecpubhex': '041f..', 'eccurvename': 'secp256r1'}</code>)
      * </li>
      * </ul>
      * @example
      * sig.initVerifyByPublicKey(rsaPrvKey)
      */
     this.initVerifyByPublicKey = function(rsaPubKey) {
 	throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" +
 	      this.algProvName;
     };

     /**
      * Initialize this object for verifying with a certficate
      * @name initVerifyByCertificatePEM
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {String} certPEM PEM formatted string of certificate
      * @since 1.0.2
      * @deprecated from crypto 1.1.5. please use init() method instead.
      * @description
      * @example
      * sig.initVerifyByCertificatePEM(certPEM)
      */
     this.initVerifyByCertificatePEM = function(certPEM) {
 	throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" +
 	    this.algProvName;
     };

     /**
      * Initialize this object for signing
      * @name initSign
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {Object} param RSAKey object of public key or associative array for ECDSA
      * @deprecated from crypto 1.1.5. please use init() method instead.
      * @description
      * Private key information will be provided as 'param' parameter and the value will be
      * following:
      * <ul>
      * <li>{@link RSAKey} object for RSA signing</li>
      * <li>associative array for ECDSA signing
      *     (ex. <code>{'ecprvhex': '1d3f..', 'eccurvename': 'secp256r1'}</code>)</li>
      * </ul>
      * @example
      * sig.initSign(prvKey)
      */
     this.initSign = function(prvKey) {
 	throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
     };

     /**
      * Updates the data to be signed or verified by a string
      * @name updateString
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {String} str string to use for the update
      * @description
      * @example
      * sig.updateString('aaa')
      */
     this.updateString = function(str) {
 	throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
     };

     /**
      * Updates the data to be signed or verified by a hexadecimal string
      * @name updateHex
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {String} hex hexadecimal string to use for the update
      * @description
      * @example
      * sig.updateHex('1f2f3f')
      */
     this.updateHex = function(hex) {
 	throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
     };

     /**
      * Returns the signature bytes of all data updates as a hexadecimal string
      * @name sign
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @return the signature bytes as a hexadecimal string
      * @description
      * @example
      * var hSigValue = sig.sign()
      */
     this.sign = function() {
 	throw "sign() not supported for this alg:prov=" + this.algProvName;
     };

     /**
      * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
      * @name signString
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {String} str string to final update
      * @return the signature bytes of a hexadecimal string
      * @description
      * @example
      * var hSigValue = sig.signString('aaa')
      */
     this.signString = function(str) {
 	throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
     };

     /**
      * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
      * @name signHex
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {String} hex hexadecimal string to final update
      * @return the signature bytes of a hexadecimal string
      * @description
      * @example
      * var hSigValue = sig.signHex('1fdc33')
      */
     this.signHex = function(hex) {
 	throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
     };

     /**
      * verifies the passed-in signature.
      * @name verify
      * @memberOf KJUR.crypto.Signature#
      * @function
      * @param {String} str string to final update
      * @return {Boolean} true if the signature was verified, otherwise false
      * @description
      * @example
      * var isValid = sig.verify('1fbcefdca4823a7(snip)')
      */
     this.verify = function(hSigVal) {
 	throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;
     };

     this.initParams = params;

     if (params !== undefined) {
 	if (params['alg'] !== undefined) {
 	    this.algName = params['alg'];
 	    if (params['prov'] === undefined) {
 		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
 	    } else {
 		this.provName = params['prov'];
 	    }
 	    this.algProvName = this.algName + ":" + this.provName;
 	    this.setAlgAndProvider(this.algName, this.provName);
 	    this._setAlgNames();
 	}

 	if (params['psssaltlen'] !== undefined) this.pssSaltLen = params['psssaltlen'];

 	if (params['prvkeypem'] !== undefined) {
 	    if (params['prvkeypas'] !== undefined) {
 		throw "both prvkeypem and prvkeypas parameters not supported";
 	    } else {
 		try {
 		    var prvKey = new RSAKey();
 		    prvKey.readPrivateKeyFromPEMString(params['prvkeypem']);
 		    this.initSign(prvKey);
 		} catch (ex) {
 		    throw "fatal error to load pem private key: " + ex;
 		}
 	    }
 	}
     }
 };

 // ====== Cipher class ============================================================
 /**
  * Cipher class to encrypt and decrypt data<br/>
  * @name KJUR.crypto.Cipher
  * @class Cipher class to encrypt and decrypt data<br/>
  * @param {Array} params parameters for constructor
  * @since jsrsasign 6.2.0 crypto 1.1.10
  * @description
  * Here is supported canonicalized cipher algorithm names and its standard names:
  * <ul>
  * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKey)</li>
  * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
  * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
  * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
  * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
  * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
  * </ul>
  * NOTE: (*) is not supported in Java JCE.<br/>
  * Currently this class supports only RSA encryption and decryption.
  * However it is planning to implement also symmetric ciphers near in the future.
  * @example
  */
 KJUR.crypto.Cipher = function(params) {
 };

 /**
  * encrypt raw string by specified key and algorithm<br/>
  * @name encrypt
  * @memberOf KJUR.crypto.Cipher
  * @function
  * @param {String} s input string to encrypt
  * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
  * @param {String} algName short/long algorithm name for encryption/decryption
  * @return {String} hexadecimal encrypted string
  * @since jsrsasign 6.2.0 crypto 1.1.10
  * @description
  * This static method encrypts raw string with specified key and algorithm.
  * @example
  * KJUR.crypto.Cipher.encrypt("aaa", pubRSAKeyObj) &rarr; "1abc2d..."
  * KJUR.crypto.Cipher.encrypt("aaa", pubRSAKeyObj, "RSAOAEP) &rarr; "23ab02..."
  */
 KJUR.crypto.Cipher.encrypt = function(s, keyObj, algName) {
     if (keyObj instanceof RSAKey && keyObj.isPublic) {
 	var algName2 = KJUR.crypto.Cipher.getAlgByKeyAndName(keyObj, algName);
 	if (algName2 === "RSA") return keyObj.encrypt(s);
 	if (algName2 === "RSAOAEP") return keyObj.encryptOAEP(s, "sha1");

 	var a = algName2.match(/^RSAOAEP(\d+)$/);
 	if (a !== null) return keyObj.encryptOAEP(s, "sha" + a[1]);

 	throw "Cipher.encrypt: unsupported algorithm for RSAKey: " + algName;
     } else {
 	throw "Cipher.encrypt: unsupported key or algorithm";
     }
 };

 /**
  * decrypt encrypted hexadecimal string with specified key and algorithm<br/>
  * @name decrypt
  * @memberOf KJUR.crypto.Cipher
  * @function
  * @param {String} hex hexadecial string of encrypted message
  * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
  * @param {String} algName short/long algorithm name for encryption/decryption
  * @return {String} hexadecimal encrypted string
  * @since jsrsasign 6.2.0 crypto 1.1.10
  * @description
  * This static method decrypts encrypted hexadecimal string with specified key and algorithm.
  * @example
  * KJUR.crypto.Cipher.decrypt("aaa", prvRSAKeyObj) &rarr; "1abc2d..."
  * KJUR.crypto.Cipher.decrypt("aaa", prvRSAKeyObj, "RSAOAEP) &rarr; "23ab02..."
  */
 KJUR.crypto.Cipher.decrypt = function(hex, keyObj, algName) {
     if (keyObj instanceof RSAKey && keyObj.isPrivate) {
 	var algName2 = KJUR.crypto.Cipher.getAlgByKeyAndName(keyObj, algName);
 	if (algName2 === "RSA") return keyObj.decrypt(hex);
 	if (algName2 === "RSAOAEP") return keyObj.decryptOAEP(hex, "sha1");

 	var a = algName2.match(/^RSAOAEP(\d+)$/);
 	if (a !== null) return keyObj.decryptOAEP(hex, "sha" + a[1]);

 	throw "Cipher.decrypt: unsupported algorithm for RSAKey: " + algName;
     } else {
 	throw "Cipher.decrypt: unsupported key or algorithm";
     }
 };

 /**
  * get canonicalized encrypt/decrypt algorithm name by key and short/long algorithm name<br/>
  * @name getAlgByKeyAndName
  * @memberOf KJUR.crypto.Cipher
  * @function
  * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
  * @param {String} algName short/long algorithm name for encryption/decryption
  * @return {String} canonicalized algorithm name for encryption/decryption
  * @since jsrsasign 6.2.0 crypto 1.1.10
  * @description
  * Here is supported canonicalized cipher algorithm names and its standard names:
  * <ul>
  * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKey)</li>
  * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
  * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
  * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
  * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
  * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
  * </ul>
  * NOTE: (*) is not supported in Java JCE.
  * @example
  * KJUR.crypto.Cipher.getAlgByKeyAndName(objRSAKey) &rarr; "RSA"
  * KJUR.crypto.Cipher.getAlgByKeyAndName(objRSAKey, "RSAOAEP") &rarr; "RSAOAEP"
  */
 KJUR.crypto.Cipher.getAlgByKeyAndName = function(keyObj, algName) {
     if (keyObj instanceof RSAKey) {
 	if (":RSA:RSAOAEP:RSAOAEP224:RSAOAEP256:RSAOAEP384:RSAOAEP512:".indexOf(algName) != -1)
 	    return algName;
 	if (algName === null || algName === undefined) return "RSA";
 	throw "getAlgByKeyAndName: not supported algorithm name for RSAKey: " + algName;
     }
     throw "getAlgByKeyAndName: not supported algorithm name: " + algName;
 }

 // ====== Other Utility class =====================================================

 /**
  * static object for cryptographic function utilities
  * @name KJUR.crypto.OID
  * @class static object for cryptography related OIDs
  * @property {Array} oidhex2name key value of hexadecimal OID and its name
  *           (ex. '2a8648ce3d030107' and 'secp256r1')
  * @since crypto 1.1.3
  * @description
  */
 KJUR.crypto.OID = new function() {
     this.oidhex2name = {
 	'2a864886f70d010101': 'rsaEncryption',
 	'2a8648ce3d0201': 'ecPublicKey',
 	'2a8648ce380401': 'dsa',
 	'2a8648ce3d030107': 'secp256r1',
 	'2b8104001f': 'secp192k1',
 	'2b81040021': 'secp224r1',
 	'2b8104000a': 'secp256k1',
 	'2b81040023': 'secp521r1',
 	'2b81040022': 'secp384r1',
 	'2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
 	'608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
 	'608648016503040302': 'SHA256withDSA',
     };
 };
/* base64x-1.1.min.js  */
/*! base64x-1.1.8 (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var KJUR; if (typeof KJUR == "undefined" || !KJUR) KJUR = {}; if (typeof KJUR.lang == "undefined" || !KJUR.lang) KJUR.lang = {}; KJUR.lang.String = function() {}; function Base64x() { } function stoBA(s) { var a = new Array(); for (var i = 0; i < s.length; i++) { a[i] = s.charCodeAt(i); } return a; } function BAtos(a) { var s = ""; for (var i = 0; i < a.length; i++) { s = s + String.fromCharCode(a[i]); } return s; } function BAtohex(a) { var s = ""; for (var i = 0; i < a.length; i++) { var hex1 = a[i].toString(16); if (hex1.length == 1) hex1 = "0" + hex1; s = s + hex1; } return s; } function stohex(s) { return BAtohex(stoBA(s)); } function stob64(s) { return hex2b64(stohex(s)); } function stob64u(s) { return b64tob64u(hex2b64(stohex(s))); } function b64utos(s) { return BAtos(b64toBA(b64utob64(s))); } function b64tob64u(s) { s = s.replace(/\=/g, ""); s = s.replace(/\+/g, "-"); s = s.replace(/\//g, "_"); return s; } function b64utob64(s) { if (s.length % 4 == 2) s = s + "=="; else if (s.length % 4 == 3) s = s + "="; s = s.replace(/-/g, "+"); s = s.replace(/_/g, "/"); return s; } function hextob64u(s) { if (s.length % 2 == 1) s = "0" + s; return b64tob64u(hex2b64(s)); } function b64utohex(s) { return b64tohex(b64utob64(s)); } var utf8tob64u, b64utoutf8; if (typeof Buffer === 'function') { utf8tob64u = function (s) { return b64tob64u(new Buffer(s, 'utf8').toString('base64')); }; b64utoutf8 = function (s) { return new Buffer(b64utob64(s), 'base64').toString('utf8'); }; } else { utf8tob64u = function (s) { return hextob64u(uricmptohex(encodeURIComponentAll(s))); }; b64utoutf8 = function (s) { return decodeURIComponent(hextouricmp(b64utohex(s))); }; } function utf8tob64(s) { return hex2b64(uricmptohex(encodeURIComponentAll(s))); } function b64toutf8(s) { return decodeURIComponent(hextouricmp(b64tohex(s))); } function utf8tohex(s) { return uricmptohex(encodeURIComponentAll(s)); } function hextoutf8(s) { return decodeURIComponent(hextouricmp(s)); } function hextorstr(sHex) { var s = ""; for (var i = 0; i < sHex.length - 1; i += 2) { s += String.fromCharCode(parseInt(sHex.substr(i, 2), 16)); } return s; } function rstrtohex(s) { var result = ""; for (var i = 0; i < s.length; i++) { result += ("0" + s.charCodeAt(i).toString(16)).slice(-2); } return result; } function hextob64(s) { return hex2b64(s); } function hextob64nl(s) { var b64 = hextob64(s); var b64nl = b64.replace(/(.{64})/g, "$1\r\n"); b64nl = b64nl.replace(/\r\n$/, ''); return b64nl; } function b64nltohex(s) { var b64 = s.replace(/[^0-9A-Za-z\/+=]*/g, ''); var hex = b64tohex(b64); return hex; } function hextoArrayBuffer(hex) { if (hex.length % 2 != 0) throw "input is not even length"; if (hex.match(/^[0-9A-Fa-f]+$/) == null) throw "input is not hexadecimal"; var buffer = new ArrayBuffer(hex.length / 2); var view = new DataView(buffer); for (var i = 0; i < hex.length / 2; i++) { view.setUint8(i, parseInt(hex.substr(i * 2, 2), 16)); } return buffer; } function ArrayBuffertohex(buffer) { var hex = ""; var view = new DataView(buffer); for (var i = 0; i < buffer.byteLength; i++) { hex += ("00" + view.getUint8(i).toString(16)).slice(-2); } return hex; } function uricmptohex(s) { return s.replace(/%/g, ""); } function hextouricmp(s) { return s.replace(/(..)/g, "%$1"); } function encodeURIComponentAll(u8) { var s = encodeURIComponent(u8); var s2 = ""; for (var i = 0; i < s.length; i++) { if (s[i] == "%") { s2 = s2 + s.substr(i, 3); i = i + 2; } else { s2 = s2 + "%" + stohex(s[i]); } } return s2; } function newline_toUnix(s) { s = s.replace(/\r\n/mg, "\n"); return s; } function newline_toDos(s) { s = s.replace(/\r\n/mg, "\n"); s = s.replace(/\n/mg, "\r\n"); return s; } KJUR.lang.String.isInteger = function(s) { if (s.match(/^[0-9]+$/)) { return true; } else if (s.match(/^-[0-9]+$/)) { return true; } else { return false; } }; KJUR.lang.String.isHex = function(s) { if (s.length % 2 == 0 && (s.match(/^[0-9a-f]+$/) || s.match(/^[0-9A-F]+$/))) { return true; } else { return false; } }; KJUR.lang.String.isBase64 = function(s) { s = s.replace(/\s+/g, ""); if (s.match(/^[0-9A-Za-z+\/]+={0,3}$/) && s.length % 4 == 0) { return true; } else { return false; } }; KJUR.lang.String.isBase64URL = function(s) { if (s.match(/[+/=]/)) return false; s = b64utob64(s); return KJUR.lang.String.isBase64(s); }; KJUR.lang.String.isIntegerArray = function(s) { s = s.replace(/\s+/g, ""); if (s.match(/^\[[0-9,]+\]$/)) { return true; } else { return false; } }; function intarystrtohex(s) { s = s.replace(/^\s*\[\s*/, ''); s = s.replace(/\s*\]\s*$/, ''); s = s.replace(/\s*/g, ''); try { var hex = s.split(/,/).map(function(element, index, array) { var i = parseInt(element); if (i < 0 || 255 < i) throw "integer not in range 0-255"; var hI = ("00" + i.toString(16)).slice(-2); return hI; }).join(''); return hex; } catch(ex) { throw "malformed integer array string: " + ex; } } var strdiffidx = function(s1, s2) { var n = s1.length; if (s1.length > s2.length) n = s2.length; for (var i = 0; i < n; i++) { if (s1.charCodeAt(i) != s2.charCodeAt(i)) return i; } if (s1.length != s2.length) return n; return -1; };/* ext/prng4-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function Arcfour(){this.i=0;this.j=0;this.S=new Array()}function ARC4init(d){var c,a,b;for(c=0;c<256;++c){this.S[c]=c}a=0;for(c=0;c<256;++c){a=(a+this.S[c]+d[c%d.length])&255;b=this.S[c];this.S[c]=this.S[a];this.S[a]=b}this.i=0;this.j=0}function ARC4next(){var a;this.i=(this.i+1)&255;this.j=(this.j+this.S[this.i])&255;a=this.S[this.i];this.S[this.i]=this.S[this.j];this.S[this.j]=a;return this.S[(a+this.S[this.i])&255]}Arcfour.prototype.init=ARC4init;Arcfour.prototype.next=ARC4next;function prng_newstate(){return new Arcfour()}var rng_psize=256;
/* ext/rng-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var rng_state;var rng_pool;var rng_pptr;function rng_seed_int(a){rng_pool[rng_pptr++]^=a&255;rng_pool[rng_pptr++]^=(a>>8)&255;rng_pool[rng_pptr++]^=(a>>16)&255;rng_pool[rng_pptr++]^=(a>>24)&255;if(rng_pptr>=rng_psize){rng_pptr-=rng_psize}}function rng_seed_time(){rng_seed_int(new Date().getTime())}if(rng_pool==null){rng_pool=new Array();rng_pptr=0;var t;if(navigator.appName=="Netscape"&&navigator.appVersion<"5"&&window.crypto){var z=window.crypto.random(32);for(t=0;t<z.length;++t){rng_pool[rng_pptr++]=z.charCodeAt(t)&255}}while(rng_pptr<rng_psize){t=Math.floor(65536*Math.random());rng_pool[rng_pptr++]=t>>>8;rng_pool[rng_pptr++]=t&255}rng_pptr=0;rng_seed_time()}function rng_get_byte(){if(rng_state==null){rng_seed_time();rng_state=prng_newstate();rng_state.init(rng_pool);for(rng_pptr=0;rng_pptr<rng_pool.length;++rng_pptr){rng_pool[rng_pptr]=0}rng_pptr=0}return rng_state.next()}function rng_get_bytes(b){var a;for(a=0;a<b.length;++a){b[a]=rng_get_byte()}}function SecureRandom(){}SecureRandom.prototype.nextBytes=rng_get_bytes;
/* ext/json-sans-eval-min.js  */
/*! Mike Samuel (c) 2009 | code.google.com/p/json-sans-eval
 */
var jsonParse=(function(){var e="(?:-?\\b(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\\b)";var j='(?:[^\\0-\\x08\\x0a-\\x1f"\\\\]|\\\\(?:["/\\\\bfnrt]|u[0-9A-Fa-f]{4}))';var i='(?:"'+j+'*")';var d=new RegExp("(?:false|true|null|[\\{\\}\\[\\]]|"+e+"|"+i+")","g");var k=new RegExp("\\\\(?:([^u])|u(.{4}))","g");var g={'"':'"',"/":"/","\\":"\\",b:"\b",f:"\f",n:"\n",r:"\r",t:"\t"};function h(l,m,n){return m?g[m]:String.fromCharCode(parseInt(n,16))}var c=new String("");var a="\\";var f={"{":Object,"[":Array};var b=Object.hasOwnProperty;return function(u,q){var p=u.match(d);var x;var v=p[0];var l=false;if("{"===v){x={}}else{if("["===v){x=[]}else{x=[];l=true}}var t;var r=[x];for(var o=1-l,m=p.length;o<m;++o){v=p[o];var w;switch(v.charCodeAt(0)){default:w=r[0];w[t||w.length]=+(v);t=void 0;break;case 34:v=v.substring(1,v.length-1);if(v.indexOf(a)!==-1){v=v.replace(k,h)}w=r[0];if(!t){if(w instanceof Array){t=w.length}else{t=v||c;break}}w[t]=v;t=void 0;break;case 91:w=r[0];r.unshift(w[t||w.length]=[]);t=void 0;break;case 93:r.shift();break;case 102:w=r[0];w[t||w.length]=false;t=void 0;break;case 110:w=r[0];w[t||w.length]=null;t=void 0;break;case 116:w=r[0];w[t||w.length]=true;t=void 0;break;case 123:w=r[0];r.unshift(w[t||w.length]={});t=void 0;break;case 125:r.shift();break}}if(l){if(r.length!==1){throw new Error()}x=x[0]}else{if(r.length){throw new Error()}}if(q){var s=function(C,B){var D=C[B];if(D&&typeof D==="object"){var n=null;for(var z in D){if(b.call(D,z)&&D!==C){var y=s(D,z);if(y!==void 0){D[z]=y}else{if(!n){n=[]}n.push(z)}}}if(n){for(var A=n.length;--A>=0;){delete D[n[A]]}}}return q.call(C,B,D)};x=s({"":x},"")}return x}})();
/* jws-3.2.min.js  */
/*! jws-3.2.2 (c) 2013-2015 Kenji Urushima | kjur.github.com/jsjws/license
 */
if(typeof KJUR=="undefined"||!KJUR){KJUR={}}if(typeof KJUR.jws=="undefined"||!KJUR.jws){KJUR.jws={}}KJUR.jws.JWS=function(){var i=KJUR.jws.JWS;this.parseJWS=function(o,q){if((this.parsedJWS!==undefined)&&(q||(this.parsedJWS.sigvalH!==undefined))){return}if(o.match(/^([^.]+)\.([^.]+)\.([^.]+)$/)==null){throw"JWS signature is not a form of 'Head.Payload.SigValue'."}var r=RegExp.$1;var m=RegExp.$2;var s=RegExp.$3;var u=r+"."+m;this.parsedJWS={};this.parsedJWS.headB64U=r;this.parsedJWS.payloadB64U=m;this.parsedJWS.sigvalB64U=s;this.parsedJWS.si=u;if(!q){var p=b64utohex(s);var n=parseBigInt(p,16);this.parsedJWS.sigvalH=p;this.parsedJWS.sigvalBI=n}var l=b64utoutf8(r);var t=b64utoutf8(m);this.parsedJWS.headS=l;this.parsedJWS.payloadS=t;if(!i.isSafeJSONString(l,this.parsedJWS,"headP")){throw"malformed JSON string for JWS Head: "+l}};function b(m,l){return utf8tob64u(m)+"."+utf8tob64u(l)}function f(n,m){var l=function(o){return KJUR.crypto.Util.hashString(o,m)};if(l==null){throw"hash function not defined in jsrsasign: "+m}return l(n)}function h(r,o,l,p,n){var q=b(r,o);var m=parseBigInt(l,16);return _rsasign_verifySignatureWithArgs(q,m,p,n)}this.verifyJWSByNE=function(n,m,l){this.parseJWS(n);return _rsasign_verifySignatureWithArgs(this.parsedJWS.si,this.parsedJWS.sigvalBI,m,l)};this.verifyJWSByKey=function(o,n){this.parseJWS(o);var l=c(this.parsedJWS.headP);var m=this.parsedJWS.headP.alg.substr(0,2)=="PS";if(n.hashAndVerify){return n.hashAndVerify(l,new Buffer(this.parsedJWS.si,"utf8").toString("base64"),b64utob64(this.parsedJWS.sigvalB64U),"base64",m)}else{if(m){return n.verifyStringPSS(this.parsedJWS.si,this.parsedJWS.sigvalH,l)}else{return n.verifyString(this.parsedJWS.si,this.parsedJWS.sigvalH)}}};this.verifyJWSByPemX509Cert=function(n,l){this.parseJWS(n);var m=new X509();m.readCertPEM(l);return m.subjectPublicKeyRSA.verifyString(this.parsedJWS.si,this.parsedJWS.sigvalH)};function c(m){var n=m.alg;var l="";if(n!="RS256"&&n!="RS512"&&n!="PS256"&&n!="PS512"){throw"JWS signature algorithm not supported: "+n}if(n.substr(2)=="256"){l="sha256"}if(n.substr(2)=="512"){l="sha512"}return l}function e(l){return c(jsonParse(l))}function k(l,q,t,n,r,s){var o=new RSAKey();o.setPrivate(n,r,s);var m=e(l);var p=o.signString(t,m);return p}function j(r,q,p,o,n){var l=null;if(typeof n=="undefined"){l=e(r)}else{l=c(n)}var m=n.alg.substr(0,2)=="PS";if(o.hashAndSign){return b64tob64u(o.hashAndSign(l,p,"binary","base64",m))}else{if(m){return hextob64u(o.signStringPSS(p,l))}else{return hextob64u(o.signString(p,l))}}}function g(q,n,p,m,o){var l=b(q,n);return k(q,n,l,p,m,o)}this.generateJWSByNED=function(s,o,r,n,q){if(!i.isSafeJSONString(s)){throw"JWS Head is not safe JSON string: "+s}var m=b(s,o);var p=k(s,o,m,r,n,q);var l=hextob64u(p);this.parsedJWS={};this.parsedJWS.headB64U=m.split(".")[0];this.parsedJWS.payloadB64U=m.split(".")[1];this.parsedJWS.sigvalB64U=l;return m+"."+l};this.generateJWSByKey=function(q,o,l){var p={};if(!i.isSafeJSONString(q,p,"headP")){throw"JWS Head is not safe JSON string: "+q}var n=b(q,o);var m=j(q,o,n,l,p.headP);this.parsedJWS={};this.parsedJWS.headB64U=n.split(".")[0];this.parsedJWS.payloadB64U=n.split(".")[1];this.parsedJWS.sigvalB64U=m;return n+"."+m};function d(r,q,p,m){var o=new RSAKey();o.readPrivateKeyFromPEMString(m);var l=e(r);var n=o.signString(p,l);return n}this.generateJWSByP1PrvKey=function(q,o,l){if(!i.isSafeJSONString(q)){throw"JWS Head is not safe JSON string: "+q}var n=b(q,o);var p=d(q,o,n,l);var m=hextob64u(p);this.parsedJWS={};this.parsedJWS.headB64U=n.split(".")[0];this.parsedJWS.payloadB64U=n.split(".")[1];this.parsedJWS.sigvalB64U=m;return n+"."+m}};KJUR.jws.JWS.sign=function(b,p,i,l,k){var j=KJUR.jws.JWS;if(!j.isSafeJSONString(p)){throw"JWS Head is not safe JSON string: "+p}var e=j.readSafeJSONString(p);if((b==""||b==null)&&e.alg!==undefined){b=e.alg}if((b!=""&&b!=null)&&e.alg===undefined){e.alg=b;p=JSON.stringify(e)}var d=null;if(j.jwsalg2sigalg[b]===undefined){throw"unsupported alg name: "+b}else{d=j.jwsalg2sigalg[b]}var c=utf8tob64u(p);var g=utf8tob64u(i);var n=c+"."+g;var m="";if(d.substr(0,4)=="Hmac"){if(l===undefined){throw"hexadecimal key shall be specified for HMAC"}var h=new KJUR.crypto.Mac({alg:d,pass:hextorstr(l)});h.updateString(n);m=h.doFinal()}else{if(d.indexOf("withECDSA")!=-1){var o=new KJUR.crypto.Signature({alg:d});o.init(l,k);o.updateString(n);hASN1Sig=o.sign();m=KJUR.crypto.ECDSA.asn1SigToConcatSig(hASN1Sig)}else{if(d!="none"){var o=new KJUR.crypto.Signature({alg:d});o.init(l,k);o.updateString(n);m=o.sign()}}}var f=hextob64u(m);return n+"."+f};KJUR.jws.JWS.verify=function(o,s,j){var l=KJUR.jws.JWS;var p=o.split(".");var d=p[0];var k=p[1];var b=d+"."+k;var q=b64utohex(p[2]);var i=l.readSafeJSONString(b64utoutf8(p[0]));var h=null;var r=null;if(i.alg===undefined){throw"algorithm not specified in header"}else{h=i.alg;r=h.substr(0,2)}if(j!=null&&Object.prototype.toString.call(j)==="[object Array]"&&j.length>0){var c=":"+j.join(":")+":";if(c.indexOf(":"+h+":")==-1){throw"algorithm '"+h+"' not accepted in the list"}}if(h!="none"&&s===null){throw"key shall be specified to verify."}if(r=="HS"){if(typeof s!="string"&&s.length!=0&&s.length%2!=0&&!s.match(/^[0-9A-Fa-f]+/)){throw"key shall be a hexadecimal str for HS* algs"}}if(typeof s=="string"&&s.indexOf("-----BEGIN ")!=-1){s=KEYUTIL.getKey(s)}if(r=="RS"||r=="PS"){if(!(s instanceof RSAKey)){throw"key shall be a RSAKey obj for RS* and PS* algs"}}if(r=="ES"){if(!(s instanceof KJUR.crypto.ECDSA)){throw"key shall be a ECDSA obj for ES* algs"}}if(h=="none"){}var m=null;if(l.jwsalg2sigalg[i.alg]===undefined){throw"unsupported alg name: "+h}else{m=l.jwsalg2sigalg[h]}if(m=="none"){throw"not supported"}else{if(m.substr(0,4)=="Hmac"){if(s===undefined){throw"hexadecimal key shall be specified for HMAC"}var g=new KJUR.crypto.Mac({alg:m,pass:hextorstr(s)});g.updateString(b);hSig2=g.doFinal();return q==hSig2}else{if(m.indexOf("withECDSA")!=-1){var f=null;try{f=KJUR.crypto.ECDSA.concatSigToASN1Sig(q)}catch(n){return false}var e=new KJUR.crypto.Signature({alg:m});e.init(s);e.updateString(b);return e.verify(f)}else{var e=new KJUR.crypto.Signature({alg:m});e.init(s);e.updateString(b);return e.verify(q)}}}};KJUR.jws.JWS.jwsalg2sigalg={HS256:"HmacSHA256",HS384:"HmacSHA384",HS512:"HmacSHA512",RS256:"SHA256withRSA",RS384:"SHA384withRSA",RS512:"SHA512withRSA",ES256:"SHA256withECDSA",ES384:"SHA384withECDSA",PS256:"SHA256withRSAandMGF1",PS384:"SHA384withRSAandMGF1",PS512:"SHA512withRSAandMGF1",none:"none",};KJUR.jws.JWS.isSafeJSONString=function(d,c,e){var f=null;try{f=jsonParse(d);if(typeof f!="object"){return 0}if(f.constructor===Array){return 0}if(c){c[e]=f}return 1}catch(b){return 0}};KJUR.jws.JWS.readSafeJSONString=function(c){var d=null;try{d=jsonParse(c);if(typeof d!="object"){return null}if(d.constructor===Array){return null}return d}catch(b){return null}};KJUR.jws.JWS.getEncodedSignatureValueFromJWS=function(b){if(b.match(/^[^.]+\.[^.]+\.([^.]+)$/)==null){throw"JWS signature is not a form of 'Head.Payload.SigValue'."}return RegExp.$1};KJUR.jws.IntDate=function(){};KJUR.jws.IntDate.get=function(b){if(b=="now"){return KJUR.jws.IntDate.getNow()}else{if(b=="now + 1hour"){return KJUR.jws.IntDate.getNow()+60*60}else{if(b=="now + 1day"){return KJUR.jws.IntDate.getNow()+60*60*24}else{if(b=="now + 1month"){return KJUR.jws.IntDate.getNow()+60*60*24*30}else{if(b=="now + 1year"){return KJUR.jws.IntDate.getNow()+60*60*24*365}else{if(b.match(/Z$/)){return KJUR.jws.IntDate.getZulu(b)}else{if(b.match(/^[0-9]+$/)){return parseInt(b)}}}}}}}throw"unsupported format: "+b};KJUR.jws.IntDate.getZulu=function(h){if(a=h.match(/(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z/)){var g=parseInt(RegExp.$1);var i=parseInt(RegExp.$2)-1;var c=parseInt(RegExp.$3);var b=parseInt(RegExp.$4);var e=parseInt(RegExp.$5);var f=parseInt(RegExp.$6);var j=new Date(Date.UTC(g,i,c,b,e,f));return ~~(j/1000)}throw"unsupported format: "+h};KJUR.jws.IntDate.getNow=function(){var b=~~(new Date()/1000);return b};KJUR.jws.IntDate.intDate2UTCString=function(b){var c=new Date(b*1000);return c.toUTCString()};KJUR.jws.IntDate.intDate2Zulu=function(f){var j=new Date(f*1000);var i=("0000"+j.getUTCFullYear()).slice(-4);var h=("00"+(j.getUTCMonth()+1)).slice(-2);var c=("00"+j.getUTCDate()).slice(-2);var b=("00"+j.getUTCHours()).slice(-2);var e=("00"+j.getUTCMinutes()).slice(-2);var g=("00"+j.getUTCSeconds()).slice(-2);return i+h+c+b+e+g+"Z"};
