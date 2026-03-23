/* @author vmthook - Command line interface handler for binflow. */
#pragma once
#include <string>
#include <vector>

class CLI
{
public:
    static bool Parse(int Argc, char* Argv[]);
    static bool IsEntry();
    static bool IsFunctions();
    static bool IsFull();
    static std::string GetPath();

private:
    static std::string Path;
    static bool Entry;
    static bool Functions;
    static bool Full;
};
