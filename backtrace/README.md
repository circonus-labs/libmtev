# backtrace/ptrace-modules

## USAGE

```
sudo /opt/backtrace/bin/ptrace --module-path=/$(pwd) $PID
```

## DESCRIPTION

This directory contains backtrace/ptrace modules that enrich backtrace reports, with information like:

- the HTTP requests being served by active threads

- keys and values of mtev_hash_tables/ck_hs

## REFERENCES

- https://help.backtrace.io/en/articles/1717563-ptrace-plugins
- https://help.backtrace.io/en/articles/1717331-plugins-for-ptrace
