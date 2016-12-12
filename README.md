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


