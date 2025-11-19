# Using EhTrace

This guide provides comprehensive instructions for using EhTrace to trace and analyze Windows binaries.

## Table of Contents

- [Quick Start](#quick-start)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Configuration](#configuration)
- [Analysis Workflows](#analysis-workflows)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Minimal Example

1. Build EhTrace (see [BUILDING.md](BUILDING.md))
2. Inject into a target process:
   ```batch
   Aload.exe notepad.exe EhTrace.dll
   ```
3. Interact with the target application
4. Collect trace data:
   ```batch
   Acleanout.exe > trace.log
   ```

## Basic Usage

### DLL Injection Methods

#### Method 1: Using Aload (Recommended)

```batch
# Inject EhTrace.dll into a new process
Aload.exe <target.exe> <path\to\EhTrace.dll>

# Example
Aload.exe C:\Windows\System32\notepad.exe x64\Release\EhTrace.dll
```

#### Method 2: Manual Injection

Use any DLL injection tool that supports:
- CreateRemoteThread
- QueueUserAPC
- SetWindowsHookEx
- Manual mapping

#### Method 3: AppInit_DLLs (Global Injection)

⚠️ **Warning**: This affects all processes and requires careful configuration.

1. Add EhTrace.dll path to registry:
   ```reg
   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
   ```
2. Set `LoadAppInit_DLLs` to 1
3. Restart affected processes

### Collecting Trace Data

#### Using Acleanout

Acleanout dumps the shared memory buffer where EhTrace logs execution events.

```batch
# Dump to console
Acleanout.exe

# Save to file
Acleanout.exe > trace.log

# Continuous monitoring
Acleanout.exe --continuous > trace.log
```

#### Shared Memory Format

EhTrace creates a shared memory section named by the traced process. Each event is 32 bytes containing:

- Thread ID
- Sequence number
- Source address (from)
- Target address (to)
- Register state snapshot
- Timestamp

### Analyzing Traces

#### Using Agasm (Disassembly and Graph Generation)

```batch
# Generate basic graph
Agasm.exe trace.log output.graph

# With symbols
Agasm.exe trace.log output.graph --symbols C:\Symbols

# With disassembly
Agasm.exe trace.log output.graph --disasm
```

#### Using WPFx (Visualization)

```batch
# Launch GUI
WPFx.exe

# Load trace file through GUI
# File → Open → Select trace.log
```

WPFx provides:
- Interactive graph visualization
- Code coverage heatmaps
- Call graph exploration
- Symbol resolution
- Flame graph generation

## Advanced Usage

### Code Coverage Analysis

To generate code coverage reports:

1. Inject EhTrace into the target
2. Exercise all features of the target application
3. Collect the trace
4. Analyze coverage using Agasm or WPFx

```batch
# Generate coverage report
Agasm.exe trace.log coverage.html --format html --coverage
```

### Fuzzing Integration (AWinAFL)

EhTrace supports AFL-style fuzzing through AWinAFL:

```batch
# Build with AFL fighter
# (ensure AFL_FIGHTER is configured in BlockFighters)

# Inject AWinAFL.dll instead of EhTrace.dll
Aload.exe target.exe prep\AWinAFL\x64\Release\AWinAFL.dll

# Use with AFL
afl-fuzz -i input -o output -D <path> -- target.exe @@
```

AWinAFL provides:
- Basic block coverage instrumentation
- Edge coverage tracking
- Crash detection and reporting
- Integration with AFL fuzzing workflow

### RoP Detection

The RoP Defender fighter detects Return-Oriented Programming attacks:

```batch
# Enable RoP defender (built-in by default)
# Inject EhTrace normally
Aload.exe suspicious.exe EhTrace.dll

# Check for RoP alerts in trace
Acleanout.exe | findstr "ROP_ALERT"
```

The RoP fighter detects:
- Unbalanced call/ret sequences
- Gadget chains
- Stack pivoting
- Unusual control flow patterns

### Key Escrow

The Key Escrow fighter intercepts cryptographic operations:

```batch
# Enable key escrow (requires InitKeyFighter)
# Inject EhTrace into crypto application
Aload.exe cryptoapp.exe EhTrace.dll

# Captured keys are logged to shared memory
# Extract with Acleanout
Acleanout.exe > keys.log
```

Intercepted operations:
- CryptGenKey
- CryptImportKey
- CryptExportKey
- CryptGenRandom
- CryptEncrypt/CryptDecrypt

### Custom Fighters

To implement custom analysis logic:

1. Edit `EhTrace/BlockFighters.cpp`
2. Add your fighter function:
   ```cpp
   void MyCustomFighter(PVOID pCtx) {
       PExecutionBlock ctx = (PExecutionBlock)pCtx;
       // Your analysis logic here
       // Access: ctx->BlockFrom, ctx->BlockTo, ctx->Registers, etc.
   }
   ```
3. Register in the fighter list:
   ```cpp
   BlockFighters myFighters[] = {
       { NULL, "MyCustomFighter", DEFENSIVE_MOVE, NO_FIGHTER, NULL, MyCustomFighter },
       // ... other fighters
   };
   ```
4. Rebuild EhTrace

## Configuration

### Environment Variables

```batch
# Symbol path (standard _NT_SYMBOL_PATH format)
set _NT_SYMBOL_PATH=srv*c:\symbols*https://msdl.microsoft.com/download/symbols

# Alternative symbol server
set _NT_ALT_SYMBOL_PATH=srv*c:\localsymbols*https://internal.symbols.server

# Trace buffer size (in pages, default 65536)
set EHTRACE_BUFFER_SIZE=131072

# Enable verbose logging
set EHTRACE_VERBOSE=1
```

### Fighter Configuration

Edit `EhTrace/BlockFighters.cpp` to enable/disable fighters:

```cpp
BlockFighters staticList[] = {
    // RoP Detection (enabled)
    { NULL, "RoPFighter", DEFENSIVE_MOVE, ROP_FIGHTER, InitRoPFighter, RoPFighter },
    
    // Key Escrow (enabled)
    { NULL, "KeyFighter", DEFENSIVE_MOVE, ESCROW_FIGHTER, InitKeyFighter, KeyFighter },
    
    // AFL Fuzzing (disabled - uncomment to enable)
    // { NULL, "AFLFighter", DEFENSIVE_MOVE, AFL_FIGHTER, InitAFLFighter, AFLFighter },
};
```

### Hook Configuration

Edit hook points in `Config.cpp`:

```cpp
HookInfo HooksConfig[] = {
    // Hook CryptGenRandom
    { "CryptGenRandom", FLAGS_POST | FLAGS_RESOLVE, NULL, NULL, 2, 3, 0, NULL },
    
    // Hook malloc/free
    { "malloc", FLAGS_PRE, NULL, NULL, 1, 1, 0, NULL },
    { "free", FLAGS_POST, NULL, NULL, 1, 1, 0, NULL },
    
    // Add your hooks here
};
```

## Analysis Workflows

### Workflow 1: Basic Code Coverage

```batch
# 1. Build EhTrace
msbuild EhTrace.sln /p:Configuration=Release /p:Platform=x64

# 2. Run target with instrumentation
Aload.exe target.exe x64\Release\EhTrace.dll

# 3. Exercise target functionality
# (interact with target application)

# 4. Collect trace
Acleanout.exe > coverage.trace

# 5. Visualize
WPFx.exe coverage.trace
```

### Workflow 2: Vulnerability Research

```batch
# 1. Inject into potentially vulnerable app
Aload.exe vulnerable.exe EhTrace.dll

# 2. Provide malicious input
vulnerable.exe < exploit.dat

# 3. Check for RoP or other anomalies
Acleanout.exe | findstr "ALERT\|WARNING\|ANOMALY"

# 4. Analyze execution path
Agasm.exe trace.log exploit_analysis.graph --disasm
```

### Workflow 3: Malware Analysis

```batch
# 1. Set up isolated environment (VM recommended)

# 2. Inject into malware sample
Aload.exe malware.exe EhTrace.dll

# 3. Allow malware to execute (safely isolated)

# 4. Collect comprehensive trace
Acleanout.exe > malware_trace.log

# 5. Analyze behavior
Agasm.exe malware_trace.log behavior.graph --symbols
WPFx.exe malware_trace.log
```

### Workflow 4: Performance Profiling

```batch
# 1. Inject into application
Aload.exe app.exe EhTrace.dll

# 2. Run performance test
app.exe --benchmark

# 3. Generate flame graph
Agasm.exe trace.log flame.svg --format flamegraph

# 4. Identify hotspots
# (analyze flame.svg to find performance bottlenecks)
```

## Troubleshooting

### Common Issues

#### Issue: Target crashes on injection

**Causes**:
- Architecture mismatch (x86 vs x64)
- Anti-debugging protection
- Incompatible fighter configuration

**Solutions**:
```batch
# Verify architecture match
dumpbin /HEADERS target.exe | findstr "machine"
dumpbin /HEADERS EhTrace.dll | findstr "machine"

# Try with minimal fighters (disable all in BlockFighters.cpp)

# Check for anti-debug
# (use x64dbg or WinDbg to verify)
```

#### Issue: No trace data collected

**Causes**:
- Shared memory not created
- Target terminated before trace collection
- Insufficient permissions

**Solutions**:
```batch
# Run as administrator
runas /user:Administrator "Aload.exe target.exe EhTrace.dll"

# Check process handles
handle.exe -a | findstr "EhTraceConfigure"

# Verify DLL loaded
tasklist /m EhTrace.dll
```

#### Issue: High performance overhead

**Causes**:
- Too many fighters enabled
- Verbose logging
- Symbol resolution overhead

**Solutions**:
- Disable unnecessary fighters
- Build Release configuration
- Pre-cache symbols
- Reduce trace buffer size

#### Issue: Symbols not resolving

**Causes**:
- Missing dbghelp.dll/symsrv.dll
- Incorrect symbol path
- Network access issues

**Solutions**:
```batch
# Verify DLLs present
dir support\dbghelp.dll
dir support\symsrv.dll

# Set symbol path
set _NT_SYMBOL_PATH=srv*c:\symbols*https://msdl.microsoft.com/download/symbols

# Test symbol server
symchk /s SRV*c:\symbols*https://msdl.microsoft.com/download/symbols target.exe
```

### Debug Mode

Build EhTrace in Debug configuration for detailed diagnostics:

```batch
msbuild EhTrace.sln /p:Configuration=Debug /p:Platform=x64

# Run with debugger attached
windbg -o Aload.exe target.exe x64\Debug\EhTrace.dll
```

### Logging

Enable verbose logging for troubleshooting:

```cpp
// In EhTrace.cpp, uncomment or add:
#define ENABLE_VERBOSE_LOGGING
```

## Performance Considerations

### Optimal Configurations

For best performance:

1. **Use Release builds**
2. **Disable unused fighters**
3. **Increase buffer size** for high-throughput tracing
4. **Use local symbol cache** to avoid network latency
5. **Profile specific threads** instead of all threads

### Performance Metrics

Expected performance (varies by target):

- **Event rate**: 30-50 million events/second
- **Overhead**: 10-30% slowdown (vs native execution)
- **Memory**: 100-500 MB for trace buffers

## Next Steps

- Review [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
- Explore example traces in the `doc/` directory
- Customize fighters for your specific use case
- Integrate with your analysis pipeline

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Contact: Shane.Macaulay@IOActive.com
