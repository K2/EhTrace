# Eh'Trace (pronounced ATrace) is a binary tracing tool for Windows.

Implemented in C but has some interesting properties that may make it suitable for tracing 
binaries when other methods are not sufficient, in particular EhTrace does not require changes to a binary
to enable traces, despite being able to collect the same information as hooker type instrumentation, zero 
knowledge is needed to inspect complete code coverage and binary execution flow, register state and more.

We maintain high performance using an adaption of some known methods for high performance tracing, yet there
is no requirement to use a debugger or enable debug/trace MSR capabilities.    

I'll be presenting/releasing the first release @ CanSecWest this year, updates to follow.

CSW16 demo of notepad generated this trace, no symbols 
![BB graph/with capstone dissassembly](https://raw.githubusercontent.com/K2/EhTrace/master/support/with-dissassembly.PNG)
![BB graph/coverage CSW16 run of notepad.exe](https://raw.githubusercontent.com/K2/EhTrace/master/support/notepad-from-CSW.PNG)


## Associated projects

* EhTrace (exe is just for testing, build as DLL) <-- meat and potatoes injection DLL that will do your blockfighting ;)
* Acleanout dump's the logs from shared memory that are created by EhTrace
* Agasm is a Glue/Dissassembly tool that might be better to use from WPFx to generate graphs (just easier to do sym's and capstone in one lib)
* Aload can load a DLL
* Aprep is a test case EXE (basically EhTrace.dll setup to build as an EXE)
* Amerger is probably just garbage not going to use
* Dia2Sharp is an attempt to not use C++/CLI since I think most people don't know/like it, but maybe not since using C++/CLI seems faster
* TestDump2 is a test of the Dia2Sharp
* WPFx is just a lil test thing just using MSAGL Graphing (soon to get GraphMaps) until I bring in a more substantional GUI (probably based on Gemini/AvalonDock/Caliburn/MahApps/MaterialDesign (whew GUI's need a lot of 3rd party ;)

### YOU NEED DBGHELP.DLL AND SYMSRV.DLL I'LL CHECK THEM IN LATER I _THINK_ THEY ARE REDISTABLE? 

More help/info on how todo whatever soon. 
