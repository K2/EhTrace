# Eh'Trace (pronounced ATrace) is a binary tracing tool for Windows.

Implemented in C but has some interesting properties that may make it suitable for tracing 
binaries when other methods are not sufficient, in particular EhTrace does not require changes to a binary
to enable traces, despite being able to collect the same information as hooker type instrumentation, zero 
knowledge is needed to inspect complete code coverage and binary execution flow, register state and more.

We maintain high performance using an adaption of some known methods for high performance tracing, yet there
is no requirement to use a debugger or enable debug/trace MSR capabilities.    

I'll be presenting/releasing the first release @ CanSecWest this year, updates to follow.

## Associated projects

* C# Symbol management
* C# GUI
