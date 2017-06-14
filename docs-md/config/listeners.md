# Listeners

Network listeners and their services are specified via configuration.

##### application.conf (snippet)

```xml
  <listeners>
    <sslconfig>
      <optional_no_ca>false</optional_no_ca>
      <certificate_file>/path/to/server.crt</certificate_file>
      <key_file>/path/to/server.key</key_file>
      <ca_chain>/path/to/ca.crt</ca_chain>
    </sslconfig>
    <consoles type="mtev_console" require_env="MTEV_CONTROL">
      <listener address="127.0.0.1" port="32322">
        <config>
          <line_protocol>telnet</line_protocol>
        </config>
      </listener>
    </consoles>
    <web type="control_dispatch" address="*">
      <config>
        <document_root>/path/to/docroot</document_root>
      </config>
      <listener port="80" />
      <listener port="443" ssl="on" />
    </web>
  </listeners>
```

This example demonstrates many powerful concepts of the libmtev configuration system.
There are three listener stanzas nested above and we'll walk through each.  The first
is the `<listener address="127.0.0.1" port="32322">`.  With this, you can telnet to
127.0.0.1 port 32322 and talk with your libmtev application.  The console is extensible
so you can add applications specific command, control, and interogation capabilities.

This listener has a `<config>` stanza underneath it that sets `line_protocol` to `telnet`.
`line_protocol` is a configuration option for listeners of type `mtev_console`.  You'll
note that the listener's `type` attribute was actually set in a parent node.  Most
systems in libmtev will recusively merge from ancestors down to the a specimen node
and use that result.  Here `type` is simply an attribute, so merging is just replacing.
This node also has an `sslconfig`, but it doesn't use it, so we'll ignore that for now.
The `require_env` attribute requires the `MTEV_CONTROL` environment variable to be set
for this listener to be active; if unspecified, it is active.

The next two listener stanzas are for port 80 and 443.  They are in a `web` node that has
both `type` and `address` attributes set (those are inherited by the listeners).  The
`config` node (child of `web`) and the `sslconfig` node (child of `listeners`) are also
inherited into the `listener` nodes.  The `config` is arbitrary and passed into the listener.
The `sslconfig` is passed into the ssl subsystem and is uniform across all listener types.

The following attributes are supported for listeners:

 * ##### type

   The type of listener simply references a named eventer callback in the system (one
   registered with `eventer_name_callback(...)`.  libmtev support four built-in listener
   types: `http_rest_api`, `mtev_wire_rest_api/1.0`, `control_dispatch`, and `mtev_console`.
   Applications can arbitrarily extend the system by naming callbacks.

 * ##### require_env

   This optionally requires conditions around an environment variable. See 
   [`require_env`](README.md#requireenv).

 * ##### address

   The address is either a filesystem path (AF_UNIX), an IPv4 address or an IPv6 address.
   The type is intuited from the input string.  If the special string `*` or `inet:*` is used,
   then the IPv4 `in_addr_any` address is used for listening. IF `inet6:*` is used, then the
   IPv6 `in_addr_any` address is used for listening.

 * ##### port

   Specifies the port on which to listen.  This has no meaning for AF_UNIX-based addresses.

 * ##### ssl

   If the value here is `on`, then the socket passes through SSL negotiation before handed
   to the underlying system driving the specified listener type.

 * ##### fanout

   If the value here is `on`, the new events created for accepted connections will be fanned
   out across threads in the event pool owning the listening socket (usually the default
   event pool).  A different pool can be selected by additionally supplying `fanout_pool`.

 * ##### fanout_pool

   If `fanout` is `on`, this will select a named pool on which to distribute new connection
   events.  The value of this attribute should be the name of an event pool.  If not pool
   exists with the specified name, the pool containing the listening event will be used.

 * ##### accept_thread

   If `accept_thread` is `on`, a new dedicated thread will be spawned to handle accepting
   new connections in a blocking fashion.

### sslconfig

The ssl config allow specification of many aspects of how SSL is negotiated with
connecting clients.  SSL config supports the follwing keys:

 * ##### layer

   This specifies the layer and options we present and is the form `<protocol>[:<option>,[<option>[,...]]]`.
   Options may be negated with an antecedent `!`.  Tokens are matched case-insensitively.

   Protocols supported (depending on openssl): `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`, `TLSv1.2`. 

   Options supported (depending on openssl): `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`, `TLSv1.2`, `cipher_server_preference`

   The default layer string is `tlsv1:all,!sslv2,!sslv3`

 * ##### certificate_file

   Specifies the path to a PEM encoded certificate file.

 * ##### key_file

   Specifies the path to a PEM encoded key file.  It must not be encrypted with a password.

 * ##### ca_chain

   Specifies the CA chaing file (PEM encoded) that should be used to validate client supplied certificates.

 * ##### crl

   Specifies a PEM encoded certificate revocation list file.  If not specified, no revocation is enforced.

 * ##### ciphers

   Specifies which ciphers should be supported.  Check the OpenSSL manual for more details.

 * ### config

   Each listener can access the `config` passed to it; see type-specific documentation.

