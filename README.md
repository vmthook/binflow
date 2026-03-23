# binflow

/* @author vmthook - Advanced binary control flow analyzer. */

binflow is a modular C++ system for binary analysis, PE parsing, and disassembly. It captures extensive data and exports them into JSON logs and visual PNG flow graphs.

## Dependencies
- **Zydis**: High-performance disassembler library.
- **nlohmann/json**: Modern JSON for C++.
- **Graphviz (C API)**: Graph layout and rendering library.
- **vcpkg**: Dependency management.

## Installation (vcpkg)
```bash
vcpkg install zydis:x64-windows-static
vcpkg install nlohmann-json:x64-windows-static
vcpkg install graphviz:x64-windows-static
```

## Build
```bash
cmake -B build -G "Visual Studio 18 2026" -A x64 -DCMAKE_TOOLCHAIN_FILE=c:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```
The executable will be generated in the `Build/` directory at the root of the project.

## Features
- **Standalone Binary**: Zero external DLLs required (Static runtime).
- **Visual Control Flow**: Automatically generates `<filename>_flow.png` during analysis using the Graphviz library.
- **High-Fidelity JSON**: Ordered logging of binary info, sections, imports, and strings.
- **Entropy Analysis**: Mathematical entropy score per section to detect packing.
- **Structural Analysis**: Basic Block discovery and Call Graph (XREF) generation.
- **User-Friendly CLI**: Pauses on usage errors to prevent instant closure on double-click.
- **Clean Codebase**: Global PascalCase, no inline comments, and clean include paths.
