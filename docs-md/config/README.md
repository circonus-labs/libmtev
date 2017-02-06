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

### lockfile

If the `lockfile` attribute is specified on the root node, libmtev will require and lock the specified file to prevent multiple invocations of the application running at once.

### require_env

Via the `mtev_conf_env_off(mtev_conf_section_t node, const char *attr)` function, applications may choose to ignore certain nodes.
The default `attr` (when NULL is specified) is `require_env`.

libmtev itself applies this, in its default form, to listeners, capabilities, logs, and modules.

Environmental controls support existence checking, equality checking and PCRE matching.  Negation is accompliation by leading the
expression with an exclamation mark: `!`.

  * ##### `<var>`

    **Example:** `"FOO"`

    **Action:** require that the "FOO" environment variable be set in order for the given node to be considered active.

  * ##### `<var>=<val>`

    **Example:** `"!FOO=42"`

    **Action:** require that the "FOO" environment variable **must not** (note the leading `!`) be set and equal to 42 in order for the given node to be considered active.

  * ##### `<var>~<regex>`

    **Example:** `"FOO~^(?i)disabled_"`

    **Action:** require that the "FOO" environment variable be set and begin with the case-insensitive string "disabled_" in order for the given node to be considered active.

Unlike other attribute inheritence within mtev_conf, the `mtev_conf_env_off` function will apply all ancestral `require_env` attributes during enforcement (including the node in question.  This allows nesting of more complex "stacked" requirements.
