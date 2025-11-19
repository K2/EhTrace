# 🤝 Contributing to EhTrace

> **Thank you for your interest in contributing to EhTrace!**

---

## 🎯 Ways to Contribute

```mermaid
mindmap
  root((🤝 Contribute))
    Code
      Bug Fixes
      New Features
      Performance Improvements
      Custom Fighters
    Documentation
      Fix Typos
      Add Examples
      Improve Clarity
      Translate
    Testing
      Report Bugs
      Test Builds
      Share Results
      Platform Testing
    Community
      Answer Questions
      Share Use Cases
      Write Tutorials
      Present Research
```

---

## 🐛 Reporting Issues

### Before Reporting

```mermaid
flowchart TD
    Start([Found an Issue])
    
    Check1{Search existing<br/>issues?}
    Check2{Still on<br/>latest version?}
    Check3{Can you<br/>reproduce it?}
    
    Update[Update to Latest]
    Search[Review Existing]
    Reproduce[Create Repro Steps]
    Report[Report Issue]
    
    Start --> Check1
    Check1 -->|No| Search
    Check1 -->|Yes| Check2
    Search --> Check2
    
    Check2 -->|No| Update
    Check2 -->|Yes| Check3
    Update --> Check3
    
    Check3 -->|Yes| Reproduce
    Check3 -->|No| End([Document Non-Repro])
    
    Reproduce --> Report
    
    style Start fill:#fff9c4,stroke:#f9a825,stroke-width:3px,color:#000
    style Report fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
    style End fill:#ef5350,stroke:#c62828,stroke-width:3px,color:#fff
```

### Issue Template

When reporting an issue, please include:

**🐛 Bug Description**
- Clear, concise description of the bug
- What you expected to happen
- What actually happened

**🔄 Reproduction Steps**
1. Step-by-step instructions to reproduce
2. Minimal test case if possible
3. Sample binaries or code (if safe to share)

**💻 Environment**
- OS version (Windows 10/11, build number)
- Visual Studio version
- EhTrace version/commit
- Target application details

**📋 Logs & Output**
- Relevant error messages
- Trace output
- Crash dumps (if applicable)
- Screenshots

**🔍 Additional Context**
- Any other relevant information
- Workarounds you've tried
- Related issues

---

## 💻 Code Contributions

### Development Workflow

```mermaid
graph LR
    subgraph Setup["⚙️ Setup"]
        Fork[Fork Repo]
        Clone[Clone Fork]
        Branch[Create Branch]
        
        style Fork fill:#e1bee7,stroke:#6a1b9a,stroke-width:2px,color:#000
        style Clone fill:#ce93d8,stroke:#7b1fa2,stroke-width:2px,color:#000
        style Branch fill:#ba68c8,stroke:#4a148c,stroke-width:2px,color:#000
    end
    
    subgraph Dev["👨‍💻 Development"]
        Code[Write Code]
        Test[Test Changes]
        Commit[Commit]
        
        style Code fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
        style Test fill:#a5d6a7,stroke:#1b5e20,stroke-width:2px,color:#000
        style Commit fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#000
    end
    
    subgraph Submit["📤 Submit"]
        Push[Push Branch]
        PR[Create PR]
        Review[Code Review]
        
        style Push fill:#fff9c4,stroke:#f9a825,stroke-width:2px,color:#000
        style PR fill:#ffe082,stroke:#f57f17,stroke-width:2px,color:#000
        style Review fill:#ffd54f,stroke:#ff6f00,stroke-width:2px,color:#000
    end
    
    Fork --> Clone --> Branch
    Branch --> Code --> Test --> Commit
    Commit --> Push --> PR --> Review
    
    style Setup fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px
    style Dev fill:#e8f5e9,stroke:#388e3c,stroke-width:3px
    style Submit fill:#fffde7,stroke:#f57f17,stroke-width:3px
```

### Step-by-Step Guide

#### 1️⃣ Fork and Clone

```bash
# Fork the repository on GitHub first, then:
git clone https://github.com/YOUR-USERNAME/EhTrace.git
cd EhTrace
git remote add upstream https://github.com/K2/EhTrace.git
```

#### 2️⃣ Create a Branch

```bash
# Create a descriptive branch name
git checkout -b feature/my-awesome-feature
# or
git checkout -b fix/issue-123
```

#### 3️⃣ Make Your Changes

- Write clean, readable code
- Follow existing code style
- Add comments for complex logic
- Update documentation as needed

#### 4️⃣ Test Your Changes

```bash
# Build the project
msbuild EhTrace.sln /p:Configuration=Release /p:Platform=x64

# Test manually
Aload.exe notepad.exe x64\Release\EhTrace.dll

# Verify no regressions
```

#### 5️⃣ Commit Your Changes

```bash
# Stage your changes
git add .

# Write a descriptive commit message
git commit -m "Add feature: detailed description

- Bullet point 1
- Bullet point 2
- Fixes #123"
```

#### 6️⃣ Push and Create PR

```bash
# Push to your fork
git push origin feature/my-awesome-feature

# Create Pull Request on GitHub
# Fill out the PR template with details
```

---

## 📝 Coding Guidelines

### C++ Style

```cpp
// Use clear, descriptive names
void ProcessBasicBlock(PExecutionBlock pCtx) {
    // Comments for non-obvious logic
    if (IsRoPGadget(pCtx)) {
        LogRoPAttempt(pCtx);
    }
    
    // Proper error handling
    if (!ValidateContext(pCtx)) {
        return;
    }
}
```

### Code Structure

```mermaid
graph TB
    subgraph Good["✅ Good Practices"]
        G1[Clear naming]
        G2[Small functions]
        G3[Error handling]
        G4[Minimal coupling]
        
        style G1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
        style G2 fill:#a5d6a7,stroke:#1b5e20,stroke-width:2px,color:#000
        style G3 fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#000
        style G4 fill:#66bb6a,stroke:#1b5e20,stroke-width:2px,color:#000
    end
    
    subgraph Bad["❌ Avoid"]
        B1[Magic numbers]
        B2[Deep nesting]
        B3[Global state]
        B4[Code duplication]
        
        style B1 fill:#ffcdd2,stroke:#c62828,stroke-width:2px,color:#000
        style B2 fill:#ef9a9a,stroke:#b71c1c,stroke-width:2px,color:#000
        style B3 fill:#e57373,stroke:#c62828,stroke-width:2px,color:#000
        style B4 fill:#ef5350,stroke:#b71c1c,stroke-width:2px,color:#fff
    end
    
    style Good fill:#e8f5e9,stroke:#388e3c,stroke-width:3px
    style Bad fill:#ffebee,stroke:#c62828,stroke-width:3px
```

### Best Practices

✅ **DO:**
- Use meaningful variable names
- Keep functions focused and small
- Handle errors gracefully
- Document complex algorithms
- Test edge cases
- Maintain backward compatibility

❌ **DON'T:**
- Use magic numbers (define constants)
- Create deep nesting (refactor)
- Introduce global state unnecessarily
- Duplicate code (extract common logic)
- Break existing functionality
- Introduce security vulnerabilities

---

## 🧪 Testing Contributions

### Testing Checklist

```mermaid
stateDiagram-v2
    [*] --> Build
    
    Build --> TestBasic: Success
    Build --> [*]: Failed
    
    state "✅ Basic Tests" as TestBasic {
        [*] --> SimpleInjection
        SimpleInjection --> TraceCapture
        TraceCapture --> DataValidation
        DataValidation --> [*]
    }
    
    TestBasic --> TestAdvanced: Pass
    
    state "🔬 Advanced Tests" as TestAdvanced {
        [*] --> ComplexApps
        ComplexApps --> EdgeCases
        EdgeCases --> Performance
        Performance --> [*]
    }
    
    TestAdvanced --> TestRegression: Pass
    
    state "🔄 Regression Tests" as TestRegression {
        [*] --> ExistingFeatures
        ExistingFeatures --> KnownIssues
        KnownIssues --> [*]
    }
    
    TestRegression --> [*]: All Pass
```

### Test Your Changes

1. **🏗️ Build Test**
   ```bash
   msbuild EhTrace.sln /p:Configuration=Debug /p:Platform=x64
   msbuild EhTrace.sln /p:Configuration=Release /p:Platform=x64
   ```

2. **⚡ Basic Functionality**
   ```bash
   # Test with simple application
   Aload.exe notepad.exe EhTrace.dll
   
   # Verify trace collection
   Acleanout.exe > test_trace.log
   ```

3. **🔍 Edge Cases**
   - Test with various target applications
   - Test different injection methods
   - Test with/without symbols
   - Test performance impact

4. **🔄 Regression Testing**
   - Verify existing features still work
   - Check that old issues don't resurface
   - Test with known working configurations

---

## 📚 Documentation Contributions

### Documentation Standards

```mermaid
graph TB
    subgraph Quality["📊 Quality Standards"]
        Clear[Clear & Concise]
        Accurate[Technically Accurate]
        Complete[Complete Examples]
        Visual[Visual Aids]
        
        style Clear fill:#c5cae9,stroke:#3949ab,stroke-width:2px,color:#000
        style Accurate fill:#9fa8da,stroke:#283593,stroke-width:2px,color:#000
        style Complete fill:#7986cb,stroke:#1a237e,stroke-width:2px,color:#fff
        style Visual fill:#5c6bc0,stroke:#283593,stroke-width:2px,color:#fff
    end
    
    subgraph Elements["✨ Include"]
        Examples[Code Examples]
        Diagrams[Mermaid Diagrams]
        Commands[Command Examples]
        Warnings[Warnings & Tips]
        
        style Examples fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#000
        style Diagrams fill:#a5d6a7,stroke:#1b5e20,stroke-width:2px,color:#000
        style Commands fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#000
        style Warnings fill:#66bb6a,stroke:#1b5e20,stroke-width:2px,color:#000
    end
    
    style Quality fill:#e8eaf6,stroke:#3949ab,stroke-width:3px
    style Elements fill:#e8f5e9,stroke:#388e3c,stroke-width:3px
```

### Documentation Types

**📖 Code Documentation**
- Inline comments for complex logic
- Function/class documentation
- API documentation

**📚 User Documentation**
- Usage guides
- Tutorials
- Examples

**🏗️ Technical Documentation**
- Architecture details
- Design decisions
- Performance considerations

---

## 🎨 Custom Fighters

### Creating a Custom Fighter

```mermaid
sequenceDiagram
    participant Dev as 👨‍💻 Developer
    participant Code as 💻 BlockFighters.cpp
    participant EhTrace as ⚡ EhTrace Core
    participant Target as 🎯 Target App
    
    Dev->>Code: Define Fighter Function
    Dev->>Code: Register in Fighter List
    Dev->>EhTrace: Build EhTrace
    
    Note over Dev,EhTrace: Runtime
    
    Target->>EhTrace: Execute Basic Block
    EhTrace->>Code: Call Fighter
    activate Code
    Code->>Code: Custom Analysis
    Code-->>EhTrace: Results
    deactivate Code
    EhTrace->>Target: Continue Execution
```

### Fighter Template

```cpp
// Custom fighter function
void MyCustomFighter(PVOID pCtx) {
    PExecutionBlock ctx = (PExecutionBlock)pCtx;
    
    // Access execution context
    ULONGLONG fromAddr = ctx->BlockFrom;
    ULONGLONG toAddr = ctx->BlockTo;
    
    // Your custom analysis logic here
    if (IsInterestingPattern(fromAddr, toAddr)) {
        LogCustomEvent(ctx);
    }
}

// Initialization function (optional)
void InitMyCustomFighter() {
    // One-time setup
    SetupCustomState();
}

// Register in BlockFighters.cpp
BlockFighters myFighters[] = {
    { 
        NULL,                       // Module filter (NULL = all)
        "MyCustomFighter",          // Name
        DEFENSIVE_MOVE,             // Move type
        NO_FIGHTER,                 // Type
        InitMyCustomFighter,        // Init function
        MyCustomFighter             // Fighter function
    },
    // ... other fighters
};
```

---

## 🏆 Recognition

```mermaid
graph TB
    Contrib[🤝 Your Contribution]
    
    Code[💻 Code Merged]
    Doc[📚 Docs Improved]
    Issue[🐛 Issue Fixed]
    Help[💬 Community Help]
    
    Thanks[🙏 Thanks]
    Credit[✨ Credits]
    Community[👥 Community Impact]
    
    Contrib --> Code
    Contrib --> Doc
    Contrib --> Issue
    Contrib --> Help
    
    Code --> Thanks
    Doc --> Thanks
    Issue --> Thanks
    Help --> Thanks
    
    Thanks --> Credit
    Thanks --> Community
    
    style Contrib fill:#fff9c4,stroke:#f9a825,stroke-width:3px,color:#000
    style Thanks fill:#81c784,stroke:#2e7d32,stroke-width:3px,color:#000
    style Credit fill:#ce93d8,stroke:#7b1fa2,stroke-width:2px,color:#000
    style Community fill:#64b5f6,stroke:#1565c0,stroke-width:2px,color:#000
```

Contributors are recognized in:
- 📝 Commit messages (co-authored)
- 📚 Documentation
- 🎉 Release notes
- 👥 Contributors list

---

## 📜 Code of Conduct

### Our Standards

✅ **Positive Environment**
- Be respectful and inclusive
- Welcome newcomers
- Provide constructive feedback
- Acknowledge contributions

❌ **Unacceptable Behavior**
- Harassment or discrimination
- Offensive language
- Personal attacks
- Publishing private information

---

## 📞 Contact

```mermaid
graph LR
    Q[❓ Questions]
    B[🐛 Bugs]
    F[💡 Features]
    C[🤝 Contribute]
    
    Q --> GitHub[GitHub Issues]
    B --> GitHub
    F --> GitHub
    C --> PR[Pull Request]
    
    GitHub --> Author[Shane Macaulay<br/>Shane.Macaulay@IOActive.com]
    PR --> Author
    
    style Q fill:#c5cae9,stroke:#3949ab,stroke-width:2px,color:#000
    style B fill:#ef5350,stroke:#c62828,stroke-width:2px,color:#fff
    style F fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#000
    style C fill:#ce93d8,stroke:#7b1fa2,stroke-width:2px,color:#000
    
    style GitHub fill:#fff9c4,stroke:#f9a825,stroke-width:3px,color:#000
    style PR fill:#c8e6c9,stroke:#388e3c,stroke-width:3px,color:#000
    style Author fill:#e1bee7,stroke:#6a1b9a,stroke-width:3px,color:#000
```

**Need Help?**
- 💬 GitHub Issues: For bugs, features, questions
- 📧 Email: Shane.Macaulay@IOActive.com
- 🌐 GitHub Discussions: For general discussion

---

> 🎯 **Together we make EhTrace better!**

Thank you for contributing to EhTrace! 🙏
