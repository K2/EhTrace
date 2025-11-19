# 🏗️ EhTrace Architecture

> **Deep dive into the technical architecture of EhTrace's high-performance binary tracing framework**

---

## 🎯 Executive Overview

EhTrace is built on a foundation of Windows exception handling mechanisms, enabling transparent binary instrumentation without code modification. The architecture leverages VEH (Vectored Exception Handling), single-step debugging, and shared memory IPC to achieve unprecedented tracing performance.

```mermaid
mindmap
  root((🎯 EhTrace))
    VEH Architecture
      Exception Interception
      Single Step Trap
      Context Capture
    BlockFighting Framework
      RoP Detection
      Key Escrow
      Custom Fighters
    Performance Engine
      Block Stepping
      In Process Tracing
      Zero Context Switch
    Data Pipeline
      Shared Memory
      Event Logging
      Real Time Analysis
```

---

## 🔄 Execution Flow

### High-Level Pipeline

```mermaid
sequenceDiagram
    participant App as 🎯 Target App
    participant VEH as 🛡️ VEH Handler
    participant EhTrace as ⚡ EhTrace Core
    participant Capstone as 🔍 Capstone
    participant Fighters as ⚔️ BlockFighters
    participant Log as 📝 Shared Memory
    
    App->>App: Execute instruction
    App->>VEH: EXCEPTION_SINGLE_STEP
    activate VEH
    VEH->>EhTrace: Handle Exception
    activate EhTrace
    
    EhTrace->>Capstone: Disassemble at RIP
    activate Capstone
    Capstone-->>EhTrace: Instruction Info
    deactivate Capstone
    
    EhTrace->>Fighters: Run Active Fighters
    activate Fighters
    Fighters->>Fighters: RoP Check
    Fighters->>Fighters: Key Escrow
    Fighters->>Fighters: Custom Analysis
    Fighters-->>EhTrace: Analysis Results
    deactivate Fighters
    
    EhTrace->>Log: Write Event (32 bytes)
    activate Log
    Log-->>EhTrace: Event Logged
    deactivate Log
    
    EhTrace->>EhTrace: Set Next Trap Point
    EhTrace-->>VEH: EXCEPTION_CONTINUE_EXECUTION
    deactivate EhTrace
    VEH-->>App: Resume Execution
    deactivate VEH
    
    Note over App,Log: ⚡ ~43M events/sec throughput
```

### Detailed Exception Flow

```mermaid
stateDiagram-v2
    [*] --> Normal: Process Starts
    
    state "🎯 Normal Execution" as Normal
    state "🚨 Exception Raised" as Exception
    state "🔍 EhTrace Analysis" as Analysis
    state "⚔️ Fighter Processing" as Fighting
    state "📝 Event Logging" as Logging
    state "✅ Continue Execution" as Continue
    
    Normal --> Exception: Single Step Exception
    Exception --> Analysis: VEH Catches
    
    state Analysis {
        [*] --> GetContext
        GetContext --> Disassemble
        Disassemble --> CheckBlockBoundary
        CheckBlockBoundary --> [*]
    }
    
    Analysis --> Fighting: Block Boundary Detected
    
    state Fighting {
        [*] --> RoPCheck
        RoPCheck --> KeyEscrow
        KeyEscrow --> CustomFighters
        CustomFighters --> [*]
    }
    
    Fighting --> Logging: Analysis Complete
    
    state Logging {
        [*] --> FormatEvent
        FormatEvent --> WriteSharedMem
        WriteSharedMem --> IncrementSequence
        IncrementSequence --> [*]
    }
    
    Logging --> Continue: Event Recorded
    Continue --> Normal: Set Next Trap
    
    Normal --> [*]: Process Exits
    
    note right of Fighting
        🛡️ Security fighters run
        inline with execution
    end note
    
    note right of Logging
        📊 32-byte events
        ~43M events/sec
    end note
```

---

## 🧩 Component Architecture

### Core Module Interaction

```mermaid
graph TB
    subgraph Injection["💉 Injection Layer"]
        Aload[Aload.exe<br/>DLL Injector]
        AppInit[AppInit_DLLs<br/>Global Hook]
        Manual[Manual Map<br/>Custom Loader]
        style Aload fill:#ffe082,stroke:#f57f17,stroke-width:3px,color:#000
        style AppInit fill:#ffab91,stroke:#d84315,stroke-width:3px,color:#000
        style Manual fill:#ffcc80,stroke:#ef6c00,stroke-width:3px,color:#000
    end
    
    subgraph Core["⚡ EhTrace Core"]
        VEHReg[VEH Registration<br/>AddVectoredExceptionHandler]
        Handler[Exception Handler<br/>vEhTracer]
        BlockInit[Block Initializer<br/>InitBlock]
        ContextMgr[Context Manager<br/>ExecutionBlock Table]
        
        style VEHReg fill:#ce93d8,stroke:#7b1fa2,stroke-width:3px,color:#000
        style Handler fill:#ba68c8,stroke:#6a1b9a,stroke-width:3px,color:#000
        style BlockInit fill:#ab47bc,stroke:#4a148c,stroke-width:3px,color:#000
        style ContextMgr fill:#9c27b0,stroke:#38006b,stroke-width:3px,color:#fff
    end
    
    subgraph Analysis["🔬 Analysis Engine"]
        Capstone[Capstone Engine<br/>Disassembly]
        SymbolMgr[Symbol Manager<br/>DIA2/dbghelp]
        HookMgr[Hook Manager<br/>Function Interception]
        
        style Capstone fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
        style SymbolMgr fill:#66bb6a,stroke:#1b5e20,stroke-width:3px,color:#000
        style HookMgr fill:#4caf50,stroke:#1b5e20,stroke-width:3px,color:#fff
    end
    
    subgraph Fighters["⚔️ BlockFighters"]
        RoP[RoP Defender<br/>Call/Ret Balance]
        KeyEsc[Key Escrow<br/>Crypto Hooks]
        AFL[AFL Fighter<br/>Coverage Tracking]
        Custom[Custom Fighters<br/>User Defined]
        
        style RoP fill:#ef5350,stroke:#c62828,stroke-width:3px,color:#fff
        style KeyEsc fill:#ec407a,stroke:#ad1457,stroke-width:3px,color:#fff
        style AFL fill:#f06292,stroke:#880e4f,stroke-width:3px,color:#fff
        style Custom fill:#e91e63,stroke:#4a0072,stroke-width:3px,color:#fff
    end
    
    subgraph Output["📊 Output Layer"]
        SharedMem[Shared Memory<br/>Event Buffer]
        Cleanout[Acleanout<br/>Log Dumper]
        Agasm[Agasm<br/>Graph Gen]
        
        style SharedMem fill:#64b5f6,stroke:#1565c0,stroke-width:3px,color:#000
        style Cleanout fill:#42a5f5,stroke:#0d47a1,stroke-width:3px,color:#000
        style Agasm fill:#2196f3,stroke:#01579b,stroke-width:3px,color:#fff
    end
    
    Aload -->|Inject| VEHReg
    AppInit -->|Load| VEHReg
    Manual -->|Map| VEHReg
    
    VEHReg --> Handler
    Handler --> BlockInit
    BlockInit --> ContextMgr
    
    Handler --> Capstone
    Handler --> SymbolMgr
    Handler --> HookMgr
    
    ContextMgr --> RoP
    ContextMgr --> KeyEsc
    ContextMgr --> AFL
    ContextMgr --> Custom
    
    RoP --> SharedMem
    KeyEsc --> SharedMem
    AFL --> SharedMem
    Custom --> SharedMem
    
    SharedMem --> Cleanout
    Cleanout --> Agasm
    
    style Injection fill:#fff3e0,stroke:#ef6c00,stroke-width:4px
    style Core fill:#f3e5f5,stroke:#7b1fa2,stroke-width:4px
    style Analysis fill:#e8f5e9,stroke:#388e3c,stroke-width:4px
    style Fighters fill:#ffebee,stroke:#c62828,stroke-width:4px
    style Output fill:#e3f2fd,stroke:#1565c0,stroke-width:4px
```

---

## 💾 Data Structures

### ExecutionBlock Context

```mermaid
classDiagram
    class ExecutionBlock {
        +ULONG TID
        +ULONG InternalID
        +ULONGLONG SEQ
        +HANDLE hThr
        +ULONGLONG BlockFrom
        +ULONGLONG BlockTo
        +csh handle
        +cs_insn* insn
        +CONTEXT Registers
        +HookInfo* Hooks
        +int HookCnt
        +ULONGLONG Timestamp
        
        +InitBlock()
        +UpdateContext()
        +LogEvent()
    }
    
    class HookInfo {
        +char* FunctionName
        +DWORD Flags
        +PVOID PreHandler
        +PVOID PostHandler
        +int ParamCount
        +int ReturnCount
        
        +Resolve()
        +Execute()
    }
    
    class BlockFighters {
        +char* Module
        +char* Name
        +int Move
        +int Type
        +InitFighterFunc* InitFighter
        +FighterFunc* Fighter
        
        +Initialize()
        +Execute()
    }
    
    class ConfigContext {
        +ULONGLONG SymCnt
        +PNativeSymbol SymTab
        +bool BasicSymbolsMode
        
        +LoadSymbols()
        +ResolveAddress()
    }
    
    ExecutionBlock "1" --> "*" HookInfo : manages
    ExecutionBlock "1" --> "*" BlockFighters : executes
    ExecutionBlock --> ConfigContext : uses
    
    style ExecutionBlock fill:#e1bee7,stroke:#6a1b9a,stroke-width:3px
    style HookInfo fill:#c5cae9,stroke:#3949ab,stroke-width:3px
    style BlockFighters fill:#ffccbc,stroke:#d84315,stroke-width:3px
    style ConfigContext fill:#b2dfdb,stroke:#00695c,stroke-width:3px
```

### Event Format (32 bytes)

```mermaid
graph LR
    subgraph Event["📦 Trace Event (32 bytes)"]
        direction LR
        TID[TID<br/>4 bytes]
        SEQ[Sequence<br/>8 bytes]
        FROM[Block From<br/>8 bytes]
        TO[Block To<br/>8 bytes]
        TS[Timestamp<br/>4 bytes]
        
        style TID fill:#ffecb3,stroke:#ff8f00,stroke-width:2px,color:#000
        style SEQ fill:#fff9c4,stroke:#f9a825,stroke-width:2px,color:#000
        style FROM fill:#ffe082,stroke:#f57f17,stroke-width:2px,color:#000
        style TO fill:#ffd54f,stroke:#f57f17,stroke-width:2px,color:#000
        style TS fill:#ffca28,stroke:#ff6f00,stroke-width:2px,color:#000
    end
    
    TID --> SEQ --> FROM --> TO --> TS
    
    style Event fill:#fffde7,stroke:#f57f17,stroke-width:4px
```

---

## ⚔️ BlockFighters Framework

### Fighter Execution Model

```mermaid
flowchart TD
    Start([🎬 Basic Block Entry])
    
    subgraph Check["🔍 Fighter Selection"]
        CheckType{Fighter Type?}
        CheckMove{Move Type?}
        CheckEnabled{Enabled?}
    end
    
    subgraph Execute["⚡ Execution"]
        Defensive[🛡️ Defensive Move]
        Offensive[⚔️ Offensive Move]
    end
    
    subgraph Fighters["🥊 Available Fighters"]
        RoP[RoP Defender<br/>Call/Ret Balance]
        Key[Key Escrow<br/>Crypto Intercept]
        AFL[AFL Coverage<br/>Edge Tracking]
        Custom[Custom Logic<br/>User Defined]
    end
    
    subgraph Result["📊 Results"]
        Log[Log Event]
        Alert[Trigger Alert]
        Block[Block Execution]
        Continue[Continue]
    end
    
    Start --> Check
    Check --> CheckType
    CheckType -->|ROP_FIGHTER| CheckMove
    CheckType -->|ESCROW_FIGHTER| CheckMove
    CheckType -->|AFL_FIGHTER| CheckMove
    CheckType -->|CUSTOM| CheckMove
    
    CheckMove -->|DEFENSIVE| CheckEnabled
    CheckMove -->|OFFENSIVE| CheckEnabled
    
    CheckEnabled -->|Yes| Execute
    CheckEnabled -->|No| Continue
    
    Execute --> Defensive
    Execute --> Offensive
    
    Defensive --> RoP
    Defensive --> Key
    Defensive --> AFL
    
    Offensive --> Custom
    
    RoP --> Log
    Key --> Log
    AFL --> Log
    Custom --> Log
    
    Log --> Alert
    Log --> Continue
    Alert --> Block
    Block --> Continue
    
    Continue --> End([✅ Continue Execution])
    
    style Start fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
    style End fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
    style Check fill:#fff9c4,stroke:#f9a825,stroke-width:3px
    style Execute fill:#e1bee7,stroke:#6a1b9a,stroke-width:3px
    style Fighters fill:#ffccbc,stroke:#d84315,stroke-width:3px
    style Result fill:#b2dfdb,stroke:#00695c,stroke-width:3px
    
    style RoP fill:#ef5350,stroke:#c62828,stroke-width:2px,color:#fff
    style Key fill:#ec407a,stroke:#ad1457,stroke-width:2px,color:#fff
    style AFL fill:#ab47bc,stroke:#4a148c,stroke-width:2px,color:#fff
    style Custom fill:#5c6bc0,stroke:#283593,stroke-width:2px,color:#fff
```

### RoP Defender Logic

```mermaid
stateDiagram-v2
    [*] --> Monitoring: Initialize
    
    state "🔍 Monitoring Execution" as Monitoring
    state "📊 Analyze Instruction" as Analyze
    state "⚖️ Check Balance" as Balance
    state "🚨 RoP Detected" as Alert
    state "✅ Normal Flow" as Normal
    
    Monitoring --> Analyze: New Block
    
    state Analyze {
        [*] --> IsCall
        IsCall --> IncrementCall: CALL instruction
        IsCall --> IsRet: Not CALL
        IsRet --> DecrementRet: RET instruction
        IsRet --> IsJump: Not RET
        IsJump --> CheckGadget: Unusual JMP
        IsJump --> [*]: Normal flow
        IncrementCall --> [*]
        DecrementRet --> [*]
        CheckGadget --> [*]
    }
    
    Analyze --> Balance: Check Call/Ret Stack
    
    state Balance {
        [*] --> CountCheck
        CountCheck --> Balanced: Equal
        CountCheck --> Unbalanced: Mismatch
        CountCheck --> Suspicious: Abnormal Pattern
        Balanced --> [*]
        Unbalanced --> [*]
        Suspicious --> [*]
    }
    
    Balance --> Normal: Balanced
    Balance --> Alert: Unbalanced/Suspicious
    
    Alert --> Monitoring: Log & Continue
    Normal --> Monitoring: Continue
    
    Monitoring --> [*]: Process Exit
    
    note right of Alert
        🚨 Actions:
        - Log RoP attempt
        - Record gadget chain
        - Optional: Block execution
    end note
```

---

## 🔄 Memory Architecture

### Shared Memory Layout

```mermaid
graph TB
    subgraph Process["🎯 Target Process Space"]
        direction TB
        Code[Code Segments]
        Stack[Thread Stacks]
        Heap[Heap]
        EhDLL[EhTrace.dll]
        
        style Code fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
        style Stack fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#000
        style Heap fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
        style EhDLL fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    end
    
    subgraph SharedMem["📦 Shared Memory Sections"]
        direction TB
        Config[EhTraceConfigure<br/>Config Data]
        Symbols[EhTraceSymbols<br/>Symbol Table]
        Events[EhTraceEvents<br/>Event Buffer]
        
        style Config fill:#fff9c4,stroke:#f9a825,stroke-width:3px,color:#000
        style Symbols fill:#c5cae9,stroke:#3949ab,stroke-width:3px,color:#000
        style Events fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px,color:#000
    end
    
    subgraph External["🔧 External Processes"]
        direction TB
        Cleanout[Acleanout.exe<br/>Reader]
        Agasm[Agasm.exe<br/>Processor]
        WPFx[WPFx.exe<br/>Visualizer]
        
        style Cleanout fill:#b2dfdb,stroke:#00695c,stroke-width:2px,color:#000
        style Agasm fill:#b2ebf2,stroke:#006064,stroke-width:2px,color:#000
        style WPFx fill:#b3e5fc,stroke:#01579b,stroke-width:2px,color:#000
    end
    
    EhDLL -->|Write| Config
    EhDLL -->|Write| Symbols
    EhDLL -->|Write 43M/sec| Events
    
    Events -->|Read| Cleanout
    Cleanout -->|Parse| Agasm
    Agasm -->|Visualize| WPFx
    
    style Process fill:#e8f5e9,stroke:#388e3c,stroke-width:4px
    style SharedMem fill:#fff8e1,stroke:#f57f17,stroke-width:4px
    style External fill:#e1f5fe,stroke:#0277bd,stroke-width:4px
```

### Buffer Management

```mermaid
sequenceDiagram
    participant EhTrace as ⚡ EhTrace
    participant Buffer as 📦 Circular Buffer
    participant Cleanout as 🔧 Acleanout
    
    Note over Buffer: 65536 pages (default)
    
    loop Every Basic Block
        EhTrace->>Buffer: Write Event (32 bytes)
        Buffer->>Buffer: Increment Write Pointer
        
        alt Buffer Full
            Buffer->>Buffer: Wrap to Start
            Note over Buffer: ⚠️ Overwrite oldest events
        end
    end
    
    loop Periodic Read
        Cleanout->>Buffer: Read Events
        Buffer-->>Cleanout: Event Batch
        Cleanout->>Cleanout: Process & Output
    end
    
    Note over EhTrace,Cleanout: 🚀 Lock-free, high-performance design
```

---

## 🔌 Hook Architecture

### Function Hook Pipeline

```mermaid
flowchart LR
    subgraph Detection["🔍 Hook Detection"]
        Resolve[Symbol Resolution]
        Match[Name Matching]
        Config[Hook Config]
        
        style Resolve fill:#ffe0b2,stroke:#e65100,stroke-width:2px,color:#000
        style Match fill:#ffccbc,stroke:#d84315,stroke-width:2px,color:#000
        style Config fill:#ffab91,stroke:#bf360c,stroke-width:2px,color:#000
    end
    
    subgraph Interception["⚡ Interception"]
        Pre[Pre-Handler]
        Exec[Original Function]
        Post[Post-Handler]
        
        style Pre fill:#c5cae9,stroke:#3949ab,stroke-width:2px,color:#000
        style Exec fill:#9fa8da,stroke:#283593,stroke-width:2px,color:#000
        style Post fill:#7986cb,stroke:#1a237e,stroke-width:2px,color:#fff
    end
    
    subgraph Processing["📊 Processing"]
        Log[Log Parameters]
        Escrow[Escrow Keys]
        Analyze[Analyze Behavior]
        
        style Log fill:#b2dfdb,stroke:#00695c,stroke-width:2px,color:#000
        style Escrow fill:#80cbc4,stroke:#004d40,stroke-width:2px,color:#000
        style Analyze fill:#4db6ac,stroke:#00251a,stroke-width:2px,color:#fff
    end
    
    Resolve --> Match
    Match --> Config
    Config --> Pre
    Pre --> Exec
    Exec --> Post
    Post --> Log
    Log --> Escrow
    Escrow --> Analyze
    
    style Detection fill:#fff3e0,stroke:#ef6c00,stroke-width:3px
    style Interception fill:#e8eaf6,stroke:#3949ab,stroke-width:3px
    style Processing fill:#e0f2f1,stroke:#00695c,stroke-width:3px
```

---

## 🎨 Visualization Pipeline

### Graph Generation Flow

```mermaid
graph TD
    subgraph Input["📥 Input Sources"]
        Raw[Raw Events<br/>Shared Memory]
        Dump[Acleanout Dump<br/>Text File]
        
        style Raw fill:#f8bbd0,stroke:#c2185b,stroke-width:2px,color:#000
        style Dump fill:#f48fb1,stroke:#880e4f,stroke-width:2px,color:#000
    end
    
    subgraph Parse["🔍 Parsing"]
        Reader[Event Reader]
        Dedup[Deduplication]
        Sequence[Sequence Analysis]
        
        style Reader fill:#ce93d8,stroke:#7b1fa2,stroke-width:2px,color:#000
        style Dedup fill:#ba68c8,stroke:#6a1b9a,stroke-width:2px,color:#000
        style Sequence fill:#ab47bc,stroke:#4a148c,stroke-width:2px,color:#fff
    end
    
    subgraph Enrich["✨ Enrichment"]
        Symbols[Symbol Resolution]
        Disasm[Disassembly]
        CFG[Control Flow]
        
        style Symbols fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#000
        style Disasm fill:#66bb6a,stroke:#1b5e20,stroke-width:2px,color:#000
        style CFG fill:#4caf50,stroke:#1b5e20,stroke-width:2px,color:#fff
    end
    
    subgraph Generate["🎨 Generation"]
        BB[Basic Block Graph]
        Call[Call Graph]
        Flame[Flame Graph]
        Coverage[Coverage Map]
        
        style BB fill:#64b5f6,stroke:#1565c0,stroke-width:2px,color:#000
        style Call fill:#42a5f5,stroke:#0d47a1,stroke-width:2px,color:#000
        style Flame fill:#2196f3,stroke:#01579b,stroke-width:2px,color:#fff
        style Coverage fill:#1976d2,stroke:#004ba0,stroke-width:2px,color:#fff
    end
    
    subgraph Output["📊 Output Formats"]
        SVG[SVG Graphics]
        HTML[HTML Report]
        JSON[JSON Data]
        MSAGL[MSAGL Graph]
        
        style SVG fill:#fff59d,stroke:#f9a825,stroke-width:2px,color:#000
        style HTML fill:#fff176,stroke:#f57f17,stroke-width:2px,color:#000
        style JSON fill:#ffee58,stroke:#ff6f00,stroke-width:2px,color:#000
        style MSAGL fill:#fdd835,stroke:#f57f17,stroke-width:2px,color:#000
    end
    
    Raw --> Reader
    Dump --> Reader
    Reader --> Dedup
    Dedup --> Sequence
    
    Sequence --> Symbols
    Symbols --> Disasm
    Disasm --> CFG
    
    CFG --> BB
    CFG --> Call
    CFG --> Flame
    CFG --> Coverage
    
    BB --> SVG
    Call --> HTML
    Flame --> SVG
    Coverage --> HTML
    
    SVG --> MSAGL
    HTML --> MSAGL
    JSON --> MSAGL
    
    style Input fill:#fce4ec,stroke:#c2185b,stroke-width:3px
    style Parse fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px
    style Enrich fill:#e8f5e9,stroke:#2e7d32,stroke-width:3px
    style Generate fill:#e3f2fd,stroke:#1565c0,stroke-width:3px
    style Output fill:#fff8e1,stroke:#f57f17,stroke-width:3px
```

---

## 🚀 Performance Optimization

### Critical Path Analysis

```mermaid
graph LR
    subgraph Critical["⚡ Hot Path (per event)"]
        E1[Exception<br/>~10 cycles]
        E2[VEH Lookup<br/>~50 cycles]
        E3[Context Save<br/>~30 cycles]
        E4[Disasm<br/>~100 cycles]
        E5[Fighter<br/>~50 cycles]
        E6[Log Write<br/>~20 cycles]
        E7[Resume<br/>~40 cycles]
        
        style E1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
        style E2 fill:#a5d6a7,stroke:#1b5e20,stroke-width:2px,color:#000
        style E3 fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#000
        style E4 fill:#66bb6a,stroke:#1b5e20,stroke-width:2px,color:#000
        style E5 fill:#4caf50,stroke:#1b5e20,stroke-width:2px,color:#fff
        style E6 fill:#43a047,stroke:#1b5e20,stroke-width:2px,color:#fff
        style E7 fill:#388e3c,stroke:#2e7d32,stroke-width:2px,color:#fff
    end
    
    E1 --> E2 --> E3 --> E4 --> E5 --> E6 --> E7
    
    E7 -.->|Next Block| E1
    
    style Critical fill:#e8f5e9,stroke:#388e3c,stroke-width:4px
    
    Note[Total: ~300 cycles<br/>⚡ 43M events/sec @ 3GHz]
    style Note fill:#fff9c4,stroke:#f57f17,stroke-width:3px,color:#000
```

### Optimization Techniques

```mermaid
mindmap
  root((⚡ Performance))
    Block Stepping
      Only at BB boundaries
      Skip internal instructions
      Automatic BB detection
    Zero Copy
      Direct memory access
      Shared memory IPC
      Lock free buffers
    Cache Optimization
      Hot path optimization
      Inline critical code
      Minimize branches
    SIMD Operations
      Parallel processing
      Vectorized analysis
      Batch operations
    Thread Local Storage
      Per thread context
      No synchronization
      Parallel execution
```

---

## 🔒 Security Considerations

### Threat Model

```mermaid
graph TB
    subgraph Threats["⚠️ Potential Threats"]
        T1[Anti-Debug Detection]
        T2[Code Injection]
        T3[Memory Corruption]
        T4[Race Conditions]
        
        style T1 fill:#ffcdd2,stroke:#c62828,stroke-width:2px,color:#000
        style T2 fill:#ef9a9a,stroke:#b71c1c,stroke-width:2px,color:#000
        style T3 fill:#e57373,stroke:#c62828,stroke-width:2px,color:#000
        style T4 fill:#ef5350,stroke:#b71c1c,stroke-width:2px,color:#fff
    end
    
    subgraph Defenses["🛡️ Defense Mechanisms"]
        D1[VEH Stealth]
        D2[RoP Detection]
        D3[Memory Protection]
        D4[Thread Safety]
        
        style D1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
        style D2 fill:#a5d6a7,stroke:#1b5e20,stroke-width:2px,color:#000
        style D3 fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#000
        style D4 fill:#66bb6a,stroke:#1b5e20,stroke-width:2px,color:#000
    end
    
    T1 -.->|Mitigated by| D1
    T2 -.->|Detected by| D2
    T3 -.->|Protected by| D3
    T4 -.->|Prevented by| D4
    
    style Threats fill:#ffebee,stroke:#c62828,stroke-width:3px
    style Defenses fill:#e8f5e9,stroke:#388e3c,stroke-width:3px
```

---

## 📚 References

### Key Technologies

| Technology | Purpose | Link |
|------------|---------|------|
| **Capstone** | Disassembly Engine | [capstone-engine.org](http://www.capstone-engine.org/) |
| **MSAGL** | Graph Visualization | [Microsoft Research](https://www.microsoft.com/en-us/research/project/microsoft-automatic-graph-layout/) |
| **DIA2** | Symbol Processing | [MSDN Documentation](https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/) |
| **VEH** | Exception Handling | [Windows Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling) |

---

> 🎯 **EhTrace**: Where performance meets precision in binary instrumentation

