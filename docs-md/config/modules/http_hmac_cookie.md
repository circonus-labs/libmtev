

# http_hmac_cookie

The http_hmac_cookie provides a safe way to persent authentication
information in http sessions.


  * **loader**: C
  * **image**: http_hmac_cookie.so

### Module Configuration

    
 * **`key`** (optional) 

   allowed: `/^.+$/`

   A hex encoded key, if none is specified a random key will be
   generated.

 * **`max_age`** (optional)  [default: `86400`]

   allowed: `/^\d+$/`

   The number of seconds the cookie will be valid for (default 1
   day).

 * **`domain`** (optional) 

   allowed: `/^.+$/`

   The "Domain" for Set-Cookie. If not specified, it will use the
   subdomain of the Host header if the Host header is at least three
   units deep. (e.g. foo.com will not do anything, bar.foo.com will
   set Domain=foo.com).

 * **`user_(\S+)`** (option) 

   allowed: `/^.*$/`

   A user and password allowed.  This should be used for testing
   only.

### Examples

#### Loading the http_hmac_cookie module.

```xml
      <noit>
        <modules>
          <generic image="http_hmac_cookie" name="http_hmac_cookie"/>
        </modules>
      </noit>
    
```

