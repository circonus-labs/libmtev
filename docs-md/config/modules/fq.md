

# fq

The fq module consumed and publishes message via fq.


  * **loader**: C
  * **image**: fq.so

### Module Configuration

    
 * **`poll_limit`** (optional)  [default: `10000`]

   allowed: `/^\d+$/`

   Maximum number of messages to handle in a single callback.
### Examples

#### Loading the fq module.

```xml
      <root>
        <modules>
          <module image="fq" name="fq">
            <config>
              <poll_limit>1000</poll_limit>
            </config>
          </module>
        </modules>
        <network>
          <mq type="fq">
            <host>localhost</host>
            <port>8765</port>
            <user>user</user>
            <pass>pass</pass>
            <exchange>exchange</exchange>
            <program>prefix:"in."</program>
          </mq>
          <mq type="fq">
            <host>localhost</host>
            <port>8765</port>
            <user>user</user>
            <pass>pass</pass>
            <exchange>exchange</exchange>
            <program>prefix:"in2."</program>
          </mq>
        </network>
      </root>
    
```

