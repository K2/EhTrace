# 📚 EhTrace Documentation Index

> **Complete documentation resources for EhTrace binary tracing framework**

---

## 🎯 Documentation Structure

```mermaid
mindmap
  root((📚 EhTrace Docs))
    Getting Started
      README.md
      Quick Start
      Installation
    Building
      BUILDING.md
      Prerequisites
      Configurations
    Usage Guide
      USAGE.md
      Workflows
      Examples
    Technical Deep Dive
      ARCHITECTURE.md
      Internals
      Performance
    Presentations
      DEFCON Slides
      Technical Papers
```

---

## 📖 Core Documentation

### 🏠 [README.md](../README.md)
**Main project overview and introduction**

Topics covered:
- ✅ Project overview and purpose
- ✅ Key features and capabilities
- ✅ Architecture overview with diagrams
- ✅ Performance benchmarks
- ✅ Component ecosystem
- ✅ Quick start guide
- ✅ License and contribution info

**Audience**: Everyone - start here!

---

### 🏗️ [BUILDING.md](../BUILDING.md)
**Complete build instructions and configurations**

Topics covered:
- ✅ Build prerequisites and tools
- ✅ Visual Studio setup
- ✅ MSBuild command-line builds
- ✅ Component-specific builds
- ✅ Configuration options
- ✅ Common build issues
- ✅ Advanced build scenarios

**Audience**: Developers building from source

---

### 🚀 [USAGE.md](../USAGE.md)
**Comprehensive usage guide with workflows**

Topics covered:
- ✅ Quick start examples
- ✅ DLL injection methods
- ✅ Trace collection
- ✅ Code coverage analysis
- ✅ Fuzzing integration (AWinAFL)
- ✅ RoP detection
- ✅ Key escrow
- ✅ Configuration options
- ✅ Analysis workflows
- ✅ Troubleshooting guide

**Audience**: Users instrumenting and analyzing binaries

---

### 🏗️ [ARCHITECTURE.md](../ARCHITECTURE.md)
**Technical architecture and implementation details**

Topics covered:
- ✅ System architecture diagrams
- ✅ Execution flow
- ✅ Component interactions
- ✅ Data structures
- ✅ BlockFighters framework
- ✅ Memory architecture
- ✅ Hook architecture
- ✅ Visualization pipeline
- ✅ Performance optimization
- ✅ Security considerations

**Audience**: Advanced users and contributors

---

## 🎓 Learning Paths

### 🟢 Beginner Path

```mermaid
journey
    title Beginner's Journey to EhTrace Mastery
    section Introduction
      Read README: 5: Reader
      Understand basics: 4: Reader
    section Setup
      Install prerequisites: 3: Builder
      Build EhTrace: 4: Builder
    section First Trace
      Run simple example: 5: User
      View output: 5: User
    section Learn More
      Read USAGE guide: 4: User
      Try workflows: 4: User
```

**Step-by-step guide:**

1. **📖 Start with [README.md](../README.md)**
   - Understand what EhTrace is
   - Learn about key features
   - Review architecture overview

2. **🏗️ Follow [BUILDING.md](../BUILDING.md)**
   - Set up build environment
   - Build EhTrace DLL
   - Build supporting tools

3. **🚀 Practice with [USAGE.md](../USAGE.md)**
   - Try quick start example
   - Inject into simple program (notepad.exe)
   - Collect and view trace data

4. **🔄 Run first workflow**
   - Follow "Basic Code Coverage" workflow
   - Generate visualizations
   - Analyze results

---

### 🟡 Intermediate Path

```mermaid
graph LR
    A[Master Basics] --> B[Advanced Workflows]
    B --> C[Custom Fighters]
    C --> D[Integration]
    
    style A fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
    style B fill:#fff9c4,stroke:#f9a825,stroke-width:2px,color:#000
    style C fill:#ffccbc,stroke:#d84315,stroke-width:2px,color:#000
    style D fill:#ce93d8,stroke:#7b1fa2,stroke-width:2px,color:#000
```

**Recommended path:**

1. ✅ Complete beginner path
2. 📚 Study [USAGE.md](../USAGE.md) workflows in detail
3. ⚔️ Experiment with BlockFighters configuration
4. 🔍 Try vulnerability research workflow
5. 🐛 Set up AWinAFL fuzzing
6. 📊 Master visualization tools (WPFx, Agasm)

---

### 🔴 Advanced Path

```mermaid
flowchart TD
    Start([Advanced User])
    
    Arch[Study ARCHITECTURE.md]
    Code[Review Source Code]
    Custom[Develop Custom Fighters]
    Perf[Performance Tuning]
    Contrib[Contribute Back]
    
    Start --> Arch
    Arch --> Code
    Code --> Custom
    Custom --> Perf
    Perf --> Contrib
    
    style Start fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
    style Arch fill:#e1bee7,stroke:#6a1b9a,stroke-width:2px,color:#000
    style Code fill:#c5cae9,stroke:#3949ab,stroke-width:2px,color:#000
    style Custom fill:#ffccbc,stroke:#d84315,stroke-width:2px,color:#000
    style Perf fill:#fff9c4,stroke:#f9a825,stroke-width:2px,color:#000
    style Contrib fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
```

**Deep dive path:**

1. 🏗️ Master [ARCHITECTURE.md](../ARCHITECTURE.md)
2. 💻 Study source code in depth
3. ⚔️ Implement custom BlockFighters
4. 🚀 Optimize for your use case
5. 🔧 Contribute improvements
6. 📝 Share findings and insights

---

## 🎪 Presentations & Research

### DEFCON 24 Presentation

**Location**: `doc/Blockfighting with a Hooker -- BLOCKFIGHTERII -- DC24.pptx`

```mermaid
graph TB
    subgraph DC24["🎪 DEFCON 24 Presentation"]
        Title[Blockfighting with a Hooker<br/>BLOCKFIGHTER II]
        Topics[RoP Defender<br/>Key Escrow<br/>Ransom Warrior]
        Demo[Live Demos<br/>Performance Metrics]
        
        style Title fill:#e1bee7,stroke:#6a1b9a,stroke-width:3px,color:#000
        style Topics fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
        style Demo fill:#fff9c4,stroke:#f9a825,stroke-width:2px,color:#000
    end
    
    style DC24 fill:#f3e5f5,stroke:#7b1fa2,stroke-width:4px
```

**Topics covered:**
- 🛡️ RoP Defender - Call/Ret balance checking
- 🔑 Key Escrow - Cryptographic key interception
- 🛡️ Ransom Warrior - Ransomware defense
- ⚡ Performance demonstrations
- 📊 Real-world use cases

---

## 🔧 Component Reference

### Core Components

| Component | Purpose | Documentation |
|-----------|---------|---------------|
| **EhTrace.dll** | Main instrumentation DLL | [README](../README.md#components) |
| **Acleanout** | Log dumper | [USAGE](../USAGE.md#collecting-trace-data) |
| **Agasm** | Graph generator | [USAGE](../USAGE.md#analyzing-traces) |
| **Aload** | DLL injector | [USAGE](../USAGE.md#dll-injection-methods) |

### Analysis Tools

| Tool | Purpose | Documentation |
|------|---------|---------------|
| **WPFx** | Graph visualization | [README](../README.md#visualization) |
| **Dia2Sharp** | Symbol processing | [ARCHITECTURE](../ARCHITECTURE.md#component-architecture) |
| **AStackFolding** | Flame graph generation | [USAGE](../USAGE.md#workflow-4-performance-profiling) |

### Security Fighters

| Fighter | Purpose | Documentation |
|---------|---------|---------------|
| **RoP Defender** | RoP attack detection | [USAGE](../USAGE.md#rop-detection) |
| **Key Escrow** | Crypto key interception | [USAGE](../USAGE.md#key-escrow) |
| **AFL Fighter** | Fuzzing instrumentation | [USAGE](../USAGE.md#fuzzing-integration-awinafl) |

---

## 💡 Use Cases

```mermaid
mindmap
  root((🎯 Use Cases))
    Security Research
      Vulnerability Discovery
      Exploit Analysis
      Malware Analysis
    Software Testing
      Code Coverage
      Execution Profiling
      Behavior Analysis
    Reverse Engineering
      Control Flow Analysis
      API Monitoring
      Binary Understanding
    Fuzzing
      AFL Integration
      Coverage Feedback
      Crash Analysis
```

### 🔒 Security Research

**Documentation**: [USAGE - Vulnerability Research Workflow](../USAGE.md#workflow-2-vulnerability-research)

Use EhTrace for:
- Finding memory corruption vulnerabilities
- Analyzing exploit effectiveness
- Understanding malware behavior
- Detecting RoP gadget chains

### 🧪 Software Testing

**Documentation**: [USAGE - Code Coverage Workflow](../USAGE.md#workflow-1-basic-code-coverage)

Use EhTrace for:
- Measuring code coverage
- Profiling performance hotspots
- Validating execution paths
- Regression testing

### 🔍 Reverse Engineering

**Documentation**: [ARCHITECTURE - Analysis Pipeline](../ARCHITECTURE.md#visualization-pipeline)

Use EhTrace for:
- Mapping control flow graphs
- Identifying key functions
- Understanding program behavior
- Symbol resolution and analysis

---

## 📚 Additional Resources

### External References

```mermaid
graph TB
    subgraph Tech["🔧 Technologies"]
        CAP[Capstone<br/>capstone-engine.org]
        VEH[Windows VEH<br/>MSDN Docs]
        DIA[DIA2 SDK<br/>Visual Studio]
        
        style CAP fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
        style VEH fill:#c5cae9,stroke:#3949ab,stroke-width:2px,color:#000
        style DIA fill:#fff9c4,stroke:#f9a825,stroke-width:2px,color:#000
    end
    
    subgraph Community["👥 Community"]
        GH[GitHub Issues]
        Email[Contact Author]
        
        style GH fill:#ffccbc,stroke:#d84315,stroke-width:2px,color:#000
        style Email fill:#ce93d8,stroke:#7b1fa2,stroke-width:2px,color:#000
    end
    
    style Tech fill:#e8f5e9,stroke:#388e3c,stroke-width:3px
    style Community fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px
```

### Technology Documentation

- **Capstone**: [http://www.capstone-engine.org/](http://www.capstone-engine.org/)
- **MSAGL**: [Microsoft Research](https://www.microsoft.com/en-us/research/project/microsoft-automatic-graph-layout/)
- **DIA2**: [MSDN Documentation](https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/)
- **VEH**: [Windows Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)

### Community & Support

- **GitHub**: [https://github.com/K2/EhTrace](https://github.com/K2/EhTrace)
- **Issues**: Open issues for bugs or feature requests
- **Email**: Shane.Macaulay@IOActive.com

---

## 🗺️ Documentation Map

```mermaid
graph TB
    Start([📚 Documentation])
    
    Q1{What do you<br/>want to do?}
    
    Learn[Learn about<br/>EhTrace]
    Build[Build from<br/>source]
    Use[Use EhTrace<br/>for tracing]
    Deep[Deep technical<br/>understanding]
    
    README[📖 README.md]
    BUILDING[🏗️ BUILDING.md]
    USAGE[🚀 USAGE.md]
    ARCH[🏗️ ARCHITECTURE.md]
    
    Start --> Q1
    Q1 -->|Learn| Learn
    Q1 -->|Build| Build
    Q1 -->|Use| Use
    Q1 -->|Understand| Deep
    
    Learn --> README
    Build --> BUILDING
    Use --> USAGE
    Deep --> ARCH
    
    style Start fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
    style Q1 fill:#fff9c4,stroke:#f9a825,stroke-width:3px,color:#000
    
    style Learn fill:#e1bee7,stroke:#6a1b9a,stroke-width:2px,color:#000
    style Build fill:#c5cae9,stroke:#3949ab,stroke-width:2px,color:#000
    style Use fill:#b2dfdb,stroke:#00695c,stroke-width:2px,color:#000
    style Deep fill:#ffccbc,stroke:#d84315,stroke-width:2px,color:#000
    
    style README fill:#ce93d8,stroke:#7b1fa2,stroke-width:3px,color:#000
    style BUILDING fill:#9fa8da,stroke:#3949ab,stroke-width:3px,color:#000
    style USAGE fill:#80cbc4,stroke:#00695c,stroke-width:3px,color:#000
    style ARCH fill:#ffab91,stroke:#d84315,stroke-width:3px,color:#000
```

---

## 📝 Quick Reference

### Essential Commands

```bash
# Build
msbuild EhTrace.sln /p:Configuration=Release /p:Platform=x64

# Inject
Aload.exe target.exe EhTrace.dll

# Collect
Acleanout.exe > trace.log

# Visualize
WPFx.exe trace.log
```

### File Locations

```
EhTrace/
├── README.md              # Project overview
├── BUILDING.md            # Build guide
├── USAGE.md               # Usage guide
├── ARCHITECTURE.md        # Technical details
├── doc/                   # Additional documentation
│   ├── README.md          # This file
│   └── *.pptx             # Presentations
├── EhTrace/               # Core DLL source
├── prep/                  # Supporting tools
└── vis/                   # Visualization tools
```

---

> 🎯 **EhTrace Documentation**: Your guide to mastering high-performance binary tracing

**Last Updated**: 2024  
**Maintained by**: Shane Macaulay (Shane.Macaulay@IOActive.com)
