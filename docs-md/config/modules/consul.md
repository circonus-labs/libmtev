

# consul

A service registration and config integration for Consul agent.


  * **loader**: C
  * **image**: consul.so

### Module Configuration

    
 * **`boot_state`** (optional)  [default: `passsing`]

   allowed: `/^(?:passing|warning|critical)$/`

   Set the initial state of service registration.
 * **`kv_prefix`** (optional) 

   allowed: `/^.*$/`

   Set an option directory prefix for loading keys from consul's KV
   store.
 * **`bearer_token`** (optional) 

   allowed: `/^.*$/`

   Set a bearer token for interactions with consul (to satisfy
   Consul ACLs).
### Examples

#### Loading the http_observer module.

```xml
      <app>
        <modules>
          <generic image="consul" name="consul"/>
        </modules>
        <consul>
          <service>
            <myservice id="{app}-{node}" port="12123">
              <check deregister_after="10m" interval="5s" HTTP="/url"/>
              <weights passing="10" warning="1"/>
              <tag>foo</tag>
              <tag>bar:baz</tag>
              <meta>
                <key>value</key>
              </meta>
            </myservice>
          </service>
        </consul>
      </app>
    
```

