

# lua_web

The lua_web module allows lua to drive http requests.


  * **loader**: C
  * **image**: lua_mtev.so

### Module Configuration

    
 * **`directory`** (optional)  [default: `/install/prefix/libexec/mtev/lua/?.lua`]

   allowed: `/^.+$/`

   This is the lua load path.  See the lua manual for more details
   on meaning and syntax.

 * **`cpath`** (optional) 

   allowed: `/^.+$/`

   This is the lua DSO load path.  See the lua manual for more
   details on meaning and syntax.

 * **`dev_mode`** (optional)  [default: `false`]

   allowed: `/^(?:true|false)$/`

   If true, instructs lua_web to use a fresh state for each request.

 * **`dispatch`** (required) 

   allowed: `/^.+$/`

   The lua module to load.

 * **`loop_assign_(.*)`** (optional) 

   allowed: `/^(.+)$/`

   Optionally assigned a `mount_[name]` to a given
   `eventer_pool_t`.  The name must match a `mount_[name]` stanza.  The value is the
   name of the eventer loop pool desired.

 * **`mount_(.*)`** (optional) 

   allowed: `/^([^:]+):([^:]+):([^:]+)(?::(.+))?$/`

   module:method:mount[:expr].  The name `mount_[name]` simply must
   be unique
      and thus allows for multiple separate lua web
   services to be mounted in a single instance. Module is the name of
   the lua module the
      system will require, the function named
   "handler" will be called. Method is the HTTP method to serve (e.g.
   GET). The mount
      is the uri "directory" that will be handled by
   this `mount_[name]` stanza.  Expr is a PCRE that further
   restricts the URIs handled.

 * **`gc_full`** (optional)  [default: `1000`]

   allowed: `/^^(?:0|[1-9]\d*)$$/`

   Specify how many yield/resume iterations may happen before a
   full garbage collection cycle is performed (0 means never).

 * **`gc_step`** (optional)  [default: `0`]

   allowed: `/^^(?:0|[1-9]\d*)$$/`

   Specify the parameter to normal lua_gc LUA_GCSTEP calls.

 * **`gc_stepmul`** (optional)  [default: `1`]

   allowed: `/^^(?:[1-9]\d*)$$/`

   Set the lua gc step multiplier.

 * **`gc_pause`** (optional)  [default: `200`]

   allowed: `/^^(?:[1-9]\d*)$$/`

   Set the lua gc pause percentage.

 * **`interrupt_mode`** (optional)  [default: `errors`]

   allowed: `/^(?:error|preempt)$/`

   Specify the behavior of asynchronous VM interrupts.

 * **`interrupt_time`** (optional) 

   allowed: `/^^\d+(?:\.\d+)?$$/`

   Specify the maximum time a lua operation may execute in a single
   eventer callback.

### Examples

#### Loading the lua web module connection webmodule to the http services.

```xml
      <noit>
        <modules>
          <module image="lua_mtev" name="lua_web">
            <config>
              <directory>/some/other/path/?.lua</directory>
              <dispatch>webmodule</dispatch>
              <mount_foo>foo:GET:/foo</mount_foo>
            </config>
          </module>
        </modules>
      </noit>
    
```

