

# lua_general

The lua_general module allows running of arbitrary lua code at
startup.


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

 * **lua_module** (required) 

   allowed: /^.+$/

   The lua module to load.

 * **lua_function** (required) 

   allowed: /^.+$/

   The lua function to run in the module.

 * **Cpreload** (optional) 

   allowed: /^.*$/

   Specify a set of luaopen_(.+) calls to make immediately after
   the context is created.  This is useful if you're writing a
   standalone interpreter or other program that needs to extend lua (without
   shipping another lua module) before you start.

 * **concurrent** (optional)  [default:false]

   allowed: /^(?:true|on|false|off)$/

   Specify if the function should be invoked in each concurrent
   eventer thread.

### Examples

#### Loading the lua general module an run somefunction from the somemodule module.

```xml
      <noit>
        <modules>
          <module image="lua_mtev" name="lua_general">
            <config>
              <directory>/some/other/path/?.lua</directory>
              <lua_module>somemodule</lua_module>
              <lua_function>somefunction</lua_function>
            </config>
          </module>
        </modules>
      </noit>
    
```

