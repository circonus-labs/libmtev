# Development

This section of the manual will discuss the ins and outs of building applications
using the libmtev APIs.  There are many APIs in the system that can be used in
an isolated fashion but they are built atop each other.

Most parts of the system rely heavily on the facilities provided in
[utils/](https://github.com/circonus-labs/libmtev/tree/master/src/utils).
The [eventer/](https://github.com/circonus-labs/libmtev/tree/master/src/eventer)
takes care not to require the configuration API directly.  Most other APIs in
the system have intricate interdependencies.  Unless your use-cases for libmtev
are very sophisticated, you need not worry about these subtleties and can
simple use the APIs you need when you need them.

Many subsystems require explicit initialization before they are used and
some subsystem initializations require prior initialiation of dependednt
subsystems.  This can cause a bit of boilerplate in your startup sequence
which will seem unnecessary at first, but when your application becomes
sufficiently complex you will appreciate it dearly.

For development reference purposes, libmtev source code contains a functional
example application that does very little but can be used as a template for
new applications.
