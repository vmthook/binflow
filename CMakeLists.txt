# @author vmthook - CMake configuration for binflow (Native GDI+ Visualizer).
cmake_minimum_required(VERSION 3.20)
project(binflow)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Build)

include_directories(include)

find_package(Zydis CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(SOURCES
    src/Main.cpp
    src/utils/FileReader.cpp
    src/pe/PEParser.cpp
    src/core/Disassembler.cpp
    src/core/Analyzer.cpp
    src/core/Formatter.cpp
    src/core/Visualizer.cpp
    src/cli/CLI.cpp
)

add_executable(binflow ${SOURCES})
target_link_libraries(binflow 
    Zydis::Zydis 
    nlohmann_json::nlohmann_json 
    gdiplus
    shlwapi
    user32
    gdi32
)
