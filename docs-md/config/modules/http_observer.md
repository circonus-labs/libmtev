

# http_observer

The http_observer module observers and exposes HTTP request/response
information.


  * **loader**: C
  * **image**: http_observer.so

### Module Configuration

    
 * **`max_count`** (optional)  [default: `10000`]

   allowed: `/^\d+$/`

   The max number of http requests to track.
 * **`max_age`** (optional)  [default: `30`]

   allowed: `/^\d+$/`

   The max time to retain completed requests.
### Examples

#### Loading the http_observer module.

```xml
      <noit>
        <modules>
          <generic image="http_observer" name="http_observer"/>
        </modules>
      </noit>
    
```

