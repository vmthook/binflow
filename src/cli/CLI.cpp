/* @author vmthook - Command line interface handler for binflow. */
#include <CLI.hpp>

std::string CLI::Path = "";
bool CLI::Entry = false;
bool CLI::Functions = false;
bool CLI::Full = false;

bool CLI::Parse(int Argc, char* Argv[])
{
    if (Argc < 2)
    {
        return false;
    }

    Path = Argv[1];
    for (int i = 2; i < Argc; ++i)
    {
        std::string Arg = Argv[i];
        if (Arg == "--entry")
        {
            Entry = true;
        }
        else if (Arg == "--functions")
        {
            Functions = true;
        }
        else if (Arg == "--full")
        {
            Full = true;
        }
    }

    return true;
}

bool CLI::IsEntry()
{
    return Entry;
}

bool CLI::IsFunctions()
{
    return Functions;
}

bool CLI::IsFull()
{
    return Full;
}

std::string CLI::GetPath()
{
    return Path;
}
