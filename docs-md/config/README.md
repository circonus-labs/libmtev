# libmtev Application Configuration

Amongst other things, libmtev provides a robust configuration system that is based on simple files and XML.  Unlike other XML-based systems libmtev forgoes the XML religion and uses a non-validated (no DTD, no relax-ng) "fast and loose" approache to XML configurations.  The configuration system allows for powerful application-defined semantics by leveraging XPath for querying the configuration, but provides simple APIs for retrieving configuration settings.  The only requirement is that the root node be named for the application.

Several of libmtev's shipped subsystems including the eventer, logging, clustering, network listeners and the module system rely on the configuration system.  Various compenents are good at getting their parts from the config and ignore stuff they don't understand or know about making the system trivially extensible to support large, custom and complex application configurations if required.

The configuration file supports includes and a directory-based backing store (for configurations that are too large and/or update too often) to enhance simple XML files.  The configuration can be updated at runtime and the new modified config written back to the original location allowing for persistent runtime-updateable configuration.

While not required, it is considered best practice to inherit attributed from parent nodes.  This is accomplished via XPath in all of the existing subsystems.  As the XML configuration system allows for arbitrary node names it allows operators to build configuration files that make sense for their deployments.

```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<example1 lockfile="/var/run/example1.lock">
</example1>
```

### Lockfile

If the `lockfile` attribute is specified on the root node, libmtev will require and lock the specified file to prevent multiple invocations of the application running at once.
