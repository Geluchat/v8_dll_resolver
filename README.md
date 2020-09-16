# v8_dll_resolver

A javascript dll resolver for v8.

Note this require 4 functions in order to work : 
* read32(addr) -> read 32bits at addr
* read64(addr) -> read 64bits at addr
* addrof(obj) -> get address of obj
* readStr(addr,tolower=false) -> read string at addr (see example script)

Example: Resolving dll on the starCTF oob challenge ([script](https://github.com/Geluchat/v8_dll_resolver/blob/master/example/oob_solver.js)):

![example](https://github.com/Geluchat/v8_dll_resolver/raw/master/example_oob.png)
