# openid-implicit-client
Simple Javascript client that implements the OpenID Connect implicit flow

This code is forked based on a blog by [Nat Sakimura](https://twitter.com/_nat_en) originally documented in this [blog](https://nat.sakimura.org/2014/12/10/making-a-javascript-openid-connect-client/)

To use this library, Include the `openidconnect.js` script;
* Set the provider and client configuration info through JSON objects;
* Call the server – login;
* In the callback page, callback.html, you will get ID Token back, so that you can put it into the cookie to handle the session.


