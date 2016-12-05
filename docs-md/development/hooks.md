# Abitrary Hooks

Building a callout API makes sense for common, structured
features in software, but occassionlly there is a need to provide
somewhat arbitrary hook points after the software is designed
and the noit_hooks system is what satisfies this need.

The design goals here are somewhat specific in that we
would like to allow for a large number of hook points at low cost
when not instrumented.  As such, a hash lookup of registered hooks
would be considered to expensive.  Additionally, we want to provide
strong, compile-time type safety as it can be all to easy to hook
something with a function with a slightly incorrect protoype that
could result in disasterous corruption or crashes (or perhaps worse
daftly subtle bugs that are punishing to troubleshoot).

The hooks system is simple a set of two macros; one allowing
for the declaration of function prototypes for registering and invoking
 specific programmer-specifiec instrumentation point and the other
providing an implementation of the registration and invocation
routines.  Due to the nature of C, the macro calling conventions are
less than elegant, but ultimately require no complicated implementation
by the programmer.

### Hook Declaration

Declaring hooks is done by calling the `NOIT_HOOK_PROTO` macro with
the name of the hook (a term that composes a valid C function name),
the arguments it expects, the type of closure (usually a void *),
and some variations on those themes that provide CPP enough info
to construct an implementation with no programmer "programming."

The declaration of a hook "foo" will yield in two functions:
`foo_hook_invoke` and `foo_hook_register`.

##### Declaring a hook "foo" (in a header)

This hook "foo" takes a `struct timeval *` as an argument in addition
to its closure.
```c
NOIT_HOOK_PROTO(foo, (struct timeval *now),
                void *, closure, (void *closure, struct timeval *now));
```

##### Implementing a hook "foo" (in a source file)

```c
NOIT_HOOK_IMPL(foo, (struct timeval *now),
               void *, closure, (void *closure, struct timeval *now),
               (closure,now));
```

### Hook Usage

Once the hook is implemented, it can be used by the application
and instrumented by code at runtime. In the below example, we'll
invoke the foo instrumentation and assuming no issues arise,
we'll invoke the original `foo_work()` function.

##### Instrumenting a dunction conditionally.

Before we instrument, suppose we have:

```c
  /* preable code */
  foo_work();
  /* postamble code */
```

Now we wish to allow programmers to add instrumentation
immediately before this code that can conditionally prevent its
executation, we would modify the above code to look like:

```c
  /* preamble code */
  struct timeval now;
  mtev_gettimeofday(&now, NULL);
  if(NOIT_HOOK_CONTINUE == foo_hook_invoke(&now)) {
       foo_work();
  }
  /* postamble code */
```

If the hook should not conditionally cause or prevent code
to run, the invoke function's return value can be ignored.

In order to register a function that allows the above execution
on every other subsequent execution one would provide the following:

```c
  static my_sample_hook(void *closure, struct timeval *now) {
    static int alt = 0;
    return (alt++ % 2) ? NOIT_HOOK_CONTINUE : NOIT_HOOK_DONE;
  }

  void my_init_fuction() {
    foo_hook_register("sample", my_sample_hook, NULL);
  }
``` 

The implementation of the hook can be elsewhere in the code, even
in a dynamically loaded module.  When the hook is regsitered (you
must orchestrate the calling of `my_init_function`, the behavior of
the `foo_work()` callsite will change and our hook will be called.
Given the above implementation, the `struct timeval` will be ignored,
but every other time we reach the call site, `foo_work()` will be
skipped due to a `NOIT_HOOK_DONE` return value.
