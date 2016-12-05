

# fq

The fq module consumed and publishes message via fq.


  * **loader**: C
  * **image**: fq.so

### Module Configuration

    No module-level options available for this module.
### Examples

#### Loading the fq module.

```xml
      <root>
        <modules>
          <module image="fq" name="fq"/>
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

