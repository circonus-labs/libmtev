

# amqp

The amqp module consumes and publishes message via AMQP (RabbitMQ).


  * **loader**: C
  * **image**: amqp.so

### Module Configuration

    No module-level options available for this module.
### Examples

#### Loading the amqp module.

```xml
      <root>
        <modules>
          <module image="amqp" name="amqp"/>
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

