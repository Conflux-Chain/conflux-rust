# Profiling

## How to enable Memory profiling

> Memory profiling is only supported on Linux platform.

To enable memory profiling, the feature `jemalloc-prof` needs to be enabled when compiling the program.

And add this to your configuration file.

```toml
profiling_listen_addr="0.0.0.0:6060"
```

Then you can get the memory perf data through endpoint `/debug/pprof/allocs`, then you use golang pprof tool to analysis it.

```sh
go tool pprof --http=: http://localhost:6060/debug/pprof/allocs
```

There is another endpoint `/debug/pprof/allocs/flamegraph` can directly return flame graph.

## CPU profiling

When `profiling_listen_addr` is settling, you can also use `/debug/pprof/cpu` to profile CPU usage