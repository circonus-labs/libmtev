

# amqp

The amqp module consumes and publishes message via AMQP (RabbitMQ).


  * **loader**: C
  * **image**: amqp.so

### Module Configuration

    
 * **`poll_limit`** (optional)  [default: `10000`]

   allowed: `/^\d+$/`

   Maximum number of messages to handle in a single callback.

### Examples

#### Loading the amqp module.

```xml
      <root>
        <modules>
          <module image="amqp" name="amqp"/>
            <config>
              <poll_limit>1000</poll_limit>
            </config>
        </modules>
        <network>
          <mq type="amqp">
            <host>localhost</host>
            <port>8765</port>
            <user>user</user>
            <pass>pass</pass>
            <exchange>exchange</exchange>
            <routingkey>foo.*</routingkey>
          </mq>
          <mq type="amqp">
            <host>localhost</host>
            <port>8765</port>
            <user>user</user>
            <pass>pass</pass>
            <exchange>exchange</exchange>
            <routingkey>bob.#</routingkey>
          </mq>
        </network>
      </root>
    
```

