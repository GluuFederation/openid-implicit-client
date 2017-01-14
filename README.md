# openid-implicit-client

Simple Javascript client that implements the OpenID Connect implicit flow

This code is forked based on a javascript library written by
[Edmund Jay](https://www.linkedin.com/in/edmundjay), and referened in a
[blog](https://nat.sakimura.org/2014/12/10/making-a-javascript-openid-connect-client/)
by [Nat Sakimura](https://twitter.com/_nat_en)

To use this library, include the `openidconnect.js` your HTML page.

* Set the provider and client configuration info through JSON objects;
* Call the server – login;
* In the callback page, callback.html, you will get ID Token back,
so that you can put it into the cookie to handle the session.

## OIDC Variables

### Supported Provider Options

List of the Identity Provider's configuration parameters <br>

*supportedProviderOptions.issuer* **(string)** - Issuer ID <br>
*supportedProviderOptions.authorization_endpoint* **(string)** - Authorization Endpoint URL <br>
*supportedProviderOptions.jwks_uri* **(string)** - JWKS URL <br>
*supportedProviderOptions.claims_parameter_supported* **(boolean)** - Claims parameter support <br>
*supportedProviderOptions.request_parameter_supported* **(boolean)** - Request parameter support <br>
*supportedProviderOptions.jwks* **(object)** - Identity Provider's JWK Set <br>

### Supported Request Options

Supported Login Request parameters <br>

*supportedRequestOptions.scope* **(string)** - Space separated scope values<br>
*supportedRequestOptions.response_type* **(string)** - Space separated response_type values<br>
*supportedRequestOptions.display* **(string)** - Display<br>
*supportedRequestOptions.max_age* **(string)** - Max_age<br>
*supportedRequestOptions.claims* **(object)**  - Claims object containing what information to return in the UserInfo endpoint and ID Token<br>
*supportedRequestOptions.claims.id_token* **(array)** - List of claims to return in the ID Token<br>
*supportedRequestOptions.claims.userinfo* **(array)** - List of claims to return in the UserInfo endpoint<br>
*supportedRequestOptions.request* **(boolean)** - Signed request object JWS. Not supported yet.<br>

### Supported Client Options

List of supported Client configuration parameters <br>

*supportedClientOptions.client_id* **(string)** - The client's client_id <br>
*supportedClientOptions.redirect_uri* **(string)** - The client's redirect_uri <br>

## OIDC Methods

### setProviderInfo(p)
_p - The Identity Provider's configuration options described in supportedProviderOptions_ <br>

Sets the Identity Provider's configuration parameters. It may be done declaring each parameter on code or using the returning information from OIDC.discover('https://op.example.com'). Returns a boolean value indicating the status of **(check what it would be returning)** <br>

###### Example:
    // set Identity Provider configuration
    OIDC.setProviderInfo( {
                          issuer: 'https:/op.example.com',
                          authorization_endpoint: 'http://op.example.com/auth.html',
                          jwks_uri: 'https://op.example.com/jwks'
                       }
                     );
    // set Identity Provider configuration using discovery information
    var discovery = OIDC.discover('https://op.example.com');
    if(var)
      OIDC.setProviderInfo(discovery);

