# Including configuration

For a variety of reasons, it can be desirable to include one configuration
file from another.  libmtev allows two forms of file include: normal and
snippet.

### Normal Includes

##### application.conf
```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<root>
  <include file="child.conf"/>
</root>
```

##### child.conf
```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<child>
  <foo></foo>
  <bar></bar>
</child>
```

Under normal includes, you can include a complete XML document at the point
of the include.  The `<include>` node is preserved, not replaced.  The root
node, `<child>` in this case, is "absorbed" and it's children are placed
directly under the `<include>` node.

Any changes made to the runtime configuration within the `<child>` tree will
be writte back to `child.conf`.

The tree above would look like
```
    root
      - include
        - foo
        - bar
```

### Snippet Includes

Snippet includes act like normal includes except that the included file is
treated as an XML snippet and thus there is no root node to "absorb."  The
elements in the snippet are placed directy under include.

##### application.conf
```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<root>
  <include file="snippet.conf" snippet="true"/>
</root>
```

##### snippet.conf
```xml
<foo></foo>
<bar></bar>
```

The tree above would look like

```
    root
      - include
        - foo
        - bar
```

### Shatter

When the runtime configuration changes, the system will serialize those changes
back to the containing XML files.  For large and rapidly changing 
configurations this can be an overwhelming load on the system.  libmtev provides
a feature called "shatter" that allows any node (other than the root) to be
annotated with a `backingstore` attribute that indicates a directory to which
underlying nodes should be written out.  Nodes and attributes are stored in
separate files and when the configuraion is subsequently modified, only changed
nodes need be added, deleted or updated.

```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<root>
  <superbigtree backingstore="/path/to/etc/superbig"/>
</root>
```
