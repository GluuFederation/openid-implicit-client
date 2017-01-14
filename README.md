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

### OIDC Variables

##### Supported Provider Options

List of the Identity Provider's configuration parameters <br>

**SupportedProviderOptions.issuer** (_string_) - Issuer ID <br>
**SupportedProviderOptions.authorization_endpoint** (_string_) - Authorization Endpoint URL <br>
**SupportedProviderOptions.jwks_uri** (_string_) - JWKS URL <br>
**SupportedProviderOptions.claims_parameter_supported** (_boolean_) - Claims parameter support <br>
**SupportedProviderOptions.request_parameter_supported** (_boolean_) - Request parameter support <br>
**SupportedProviderOptions.jwks** (_object_) - Identity Provider's JWK Set <br>

##### Supported Request Options

Supported Login Request parameters <br>

  **SupportedRequestOptions.scope** (_string_) - Space separated scope values<br>
  **SupportedRequestOptions.response_type** (_string_) - Space separated response_type values<br>
  **SupportedRequestOptions.display** (_string_) - Display<br>
  **SupportedRequestOptions.max_age** (_string_) - Max_age<br>
  **SupportedRequestOptions.claims** (_object_)  - Claims object containing what information to return in the UserInfo endpoint and ID Token<br>
  **SupportedRequestOptions.claims.id_token** (_array_) - List of claims to return in the ID Token<br>
  **SupportedRequestOptions.claims.userinfo** (_array_) - List of claims to return in the UserInfo endpoint<br>
  **SupportedRequestOptions.request** (_boolean_) - Signed request object JWS. Not supported yet.<br>

##### Supported Client Options

  List of supported Client configuration parameters <br>

  **SupportedClientOptions.client_id** (_string_) - The client's client_id <br>
  **SupportedClientOptions.redirect_uri** (_string_) - The client's redirect_uri <br>

### OIDC Methods
