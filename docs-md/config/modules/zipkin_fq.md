

# zipkin_fq

The zipkin_fq module publishes Zipkin traces via Fq.


  * **loader**: C
  * **image**: zipkin_fq.so

### Module Configuration

    
 * **`host`** (optional)  [default: `127.0.0.1`]

   allowed: `/^.+$/`

   The Fq host.
 * **`port`** (optional)  [default: `8765`]

   allowed: `/^\d+$/`

   The Fq port.
 * **`user`** (optional)  [default: `mtev`]

   allowed: `/^.+$/`

   The Fq user.
 * **`pass`** (optional)  [default: `mtev`]

   allowed: `/^.+$/`

   The Fq pass.
 * **`exchange`** (optional)  [default: `logging`]

   allowed: `/^.+$/`

   The Fq exchange.
 * **`route_prefix`** (optional)  [default: `scribe.zipkin.`]

   allowed: `/^.+$/`

   The routing prefix to which the traceid is appended.
### Examples

#### Loading the zipkin_fq module.

```xml
      <noit>
        <modules>
          <generic image="zipkin_fq" name="zipkin_fq"/>
        </modules>
      </noit>
    
```

