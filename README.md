<h3><em>NOTE: This project is under active development. Documentation, tutorials
and a number features are in the works.</em></h3>

# **flame_prof**

## Overview
 
**flame_prof** is a general-purpose Erlang profiler a little like OTP's
**fprof**,  except ...

+ It generates Linux [perf_events](https://en.wikipedia.org/wiki/Perf_(Linux))
script [output](https://linux.die.net/man/1/perf-script) intended to be
consumed by, and analysed with, [a fork of Netflix's Flamescope](https://github.com/ebegumisa/flamescope).

+ It uses a call-stack sampling approach rather than attempting to measure each
individual call. So it does not _need_ to use Erlang tracing.

+ It retains calling process information including process status, memory usage,
message queue lengths and garbage collection info.

+ Provides control over output file writing (e.g. sample flush frequency, output
file rotation).

+ It provides means to automatically select processes to be profiled
(e.g. top 100 by reductions). Automatically triggering profiling in controlled
manner is coming soon.

## Screenshots

TODO

## Build

    $ rebar3 compile