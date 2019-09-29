

# zipkin_jaeger

The zipkin_jaeger module publishes Zipkin traces to Jaeger.


  * **loader**: C
  * **image**: zipkin_jaeger.so

### Module Configuration

    
 * **`host`** (optional)  [default: `127.0.0.1`]

   allowed: `/^.+$/`

   The jaeger collector host.

 * **`port`** (optional)  [default: `9411`]

   allowed: `/^\d+$/`

   The jaeger collector port.

 * **`period`** (optional)  [default: `500`]

   allowed: `/^\d+$/`

   The submission frequency in ms.

 * **`max_batch`** (optional)  [default: `500`]

   allowed: `/^\d+$/`

   The submission max batch size.

 * **`backlog`** (optional)  [default: `5000`]

   allowed: `/^\d+$/`

   The max backlog before spans are dropped.

 * **`retries`** (optional)  [default: `0`]

   allowed: `/^\d+$/`

   The number of HTTP retries upon failure..

### Examples

#### Loading the zipkin_jaeger module.

```xml
      <noit>
        <modules>
          <generic image="zipkin_jaeger" name="zipkin_jaeger"/>
        </modules>
      </noit>
    
```

