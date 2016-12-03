# Dynamically Loadable Modules

The libmtev library supports loading dynamically loadable modules that can provide
optional features to an appliction or change the behavior of exisitng code via hooks.

There are two types of modules in the core libmtev sytems "generics" and "loaders."
Loaders know how to load generics.  The only built-in module is the "C" loader which
knows how to load architecture-appropriate shared objects.

There are several modules that ship with libmtev (though engineers can build more as
a part of their application design).  These modules are described in the modules
section of the manual.

Modules are all configured under the top-level `<modules>` node in the configuration.

##### application.conf
```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<application>
  <modules directory="../modules">
    <generic image="zipkin_fq" name="zipkin_fq">
    </generic>
    <generic image="lua_mtev" name="lua_general">
      <config>
        <directory>../modules/lua-support/?.lua;./lua-examples/?.lua;{package.path}</directory>
        <cpath>../modules/mtev_lua/?.so;{package.cpath}</cpath>
        <lua_module>luatest</lua_module>
        <lua_function>onethread</lua_function>
      </config>
    </generic>
  </modules>
</application>
```

The `<modules>` node takes an optional `directory` attribute that specified where dynamic modules should
be found on the filesystem.  If omitted, the directory in which modules were installed as a part of your
libmtev install will be used.  Typically, this attribute is omitted unless you are developing new modules.
The attribute acts as a search path and both ':' and ';' can be used as separators between directory entries.
If the module cannot be loaded from any of the specified directories, the loader will attempt a fallback
to the installation's default module directory.

Like other parts of the sytem `<config>` blocks are ancestrally merged.

The `<generic>` stanzas instruct the system to load a module.  The above config loads the `zipkin_fq` module
from the `zipkin_fq` binary image (`zipkin_fq.so` on ELF systems and `zipkin_fq.bundle` on mach-o systems like Mac OS X)
with no configuration.  It also loads the `lua_general` module from the `lua_mtev` binary image with a configuration.
