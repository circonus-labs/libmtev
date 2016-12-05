

# lua_web

The lua_web module allows lua to drive http requests.


  * **loader**: C
  * **image**: lua_mtev.so

### Module Configuration

    
 * **directory** (optional)  [default:/install/prefix/libexec/mtev/lua/?.lua]

   allowed: /^.+$/

   This is the lua load path.  See the lua manual for more details
   on meaning and syntax.

 * **cpath** (optional) 

   allowed: /^.+$/

   This is the lua DSO load path.  See the lua manual for more
   details on meaning and syntax.

 * **dispatch** (required) 

   allowed: /^.+$/

   The lua module to load.

 * **mount_(.*)** (optional) 

   allowed: /^[^:]+:[^:]+:[^:]+(:.+)?$/

    module:method:mount[:expr]

### Examples

#### Loading the lua web module connection webmodule to the http services.

```xml
      <noit>
        <modules>
          <module image="lua_mtev" name="lua_web">
            <config>
              <directory>/some/other/path/?.lua</directory>
              <dispatch>webmodule</dispatch>
              <mount_foo>foo:handler:/foo</mount_foo>
            </config>
          </module>
        </modules>
      </noit>
    
```

