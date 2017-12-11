# PCVisor

## folder structure

* [`build/`](https://github.com/huxh10/PCVisor/tree/master/build) - store the built staff
* [`code/`](https://github.com/huxh10/PCVisor/tree/master/code) - source code
* [`test/rules/`](https://github.com/huxh10/PCVisor/tree/master/test/rules) - test rules from classbench
* [`test/p_rules/`](https://github.com/huxh10/PCVisor/tree/master/test/p_rules) - test prefix rules derived from classbench
* [`test/traces/`](https://github.com/huxh10/PCVisor/tree/master/test/traces) - traces corresponding to the above rules
* [`scripts/`](https://github.com/huxh10/PCVisor/tree/master/scripts) - scripts for rule operations and running programs

## how to run

``` Bash
$ make clean && make
# HyperSplit
$ ./build/pc_algo -a 0 -r test/rules/fw1_10K -t test/traces/fw1_10K_trace
# TSS
$ ./build/pc_algo -a 1 -r test/p_rules/fw1_10K -t test/traces/fw1_10K_trace
```
