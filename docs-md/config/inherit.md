# Inheritance

Unless otherwise specified, elements and attributes are inherited from
all ancestors.  As is typical with inheritance, the youngest/deepest
value overrides values of ancestors.  If the value requested is a set
of key/value pairs, the top-most ancestor is queried, then its
child is queried, merging values, replacing conflicts and so on until
the youngest/deepest node is reached.

The C API `mtev_conf_get_hash` and `mtev_conf_get_namespaced_hash`
implement this functionality; as long as those functions are used to
convert configuration stanzas into hashes for internal use, the
developer and the operator get all the advantages of sophisticated
configuration reuse.

When attributes are extracted, developers should use the the XPath
practice of `ancestor-or-self::node()/@name` for an attribute named `name`.

### Simple (implicit) inheritance

##### simple.conf (snippet)
```xml
      <a foo="bar">
        <config>
          <key1>val a 1</key1>
          <key2>val a 2</key2>
        </config>
        <b quux="baz">
          <config>
            <key1>val b 1</key1>
            <key3>val b 3</key3>
          </config>
          <c foo="meme" />
        </b>
      </a>
```

When looking at the "foo" attribute we see the following values at nodes:

    * at `a`, foo="bar"
    * at `b`, foo="bar"
    * at `c`, foo="meme"

When looking at the "quux" attribute we see the following values at nodes:

    * at `a`, foo=(none)
    * at `b`, foo="baz"
    * at `c`, foo="baz"

When looking at the key/value set "config" we see the following values at nodes:

    * at `a`, `{ key1: "val a 1", key2: "val a 2" }`
    * at `b`, `{ key1: "val b 1", key2: "val a 2", key3: "val b 3" }`
    * at `c`, `{ key1: "val b 1", key2: "val a 2", key3: "val b 3" }`

This inheritance model allows for "non-repetitive" configuration
approaches: "express yourself once and reuse."


### Complex (explicit) Inheritance

Sometimes it is useful to define a configuration key/value set
for reuse, but the strict parent-child inheritance model is awkward.
Under these circumstances, the explicit inheritance often solves the
issue at hand.  With explicit inheritance, a configuration can inherit
from another named node elsewhere in the configuration.

The `<config>` stanzas (and others) can be identified, as is typical in XML, with
the `id` attribute: `<config id="sample">.  Additionally, any config
may explicitly specify that it inherits from a named config by
specifying the `inherit` attribute.

Any `<config>`, A, which has the `inherit` attribute will first
inherit from its most direct parent, then supplement/replace those
key/values with the configuration whose `id` attribute matches the
`inherit` attribute of A, and finally supplement/replace those
key/values with key/values directly beneath A.  The entire tree is
searched for a node whose `id` matches A's `inherit` attribute.

##### complex.conf (snippet)
```xml
  <config name="A">
    <key1>a</key1>
    <key2>b</key2>
    <key3>c</key3>
    <config name="C" inherit="bob">
      <key1>AAA</key1>
      <key4>DDD</key4>
    </config>
  </config>
  <x>
    <y>
      <z>
        <config name="B" id="bob">
          <key2>bobB</key2>
          <key5>bobE</key5>
        </config>
      </z>
    </y>
  </x>
```

The config named "A" contains:

    * key1 = a
    * key2 = b
    * key3 = c

The config named "C" contains:

    * key1 = AAA
    * key2 = bobB
    * key3 = c
    * key4 = DDD
    * key5 = bobE

It should be noted hat all config's that include the one named "B" above
follows this same inheritance model.
