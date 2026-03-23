/* @author vmthook - Basic file reading utilities for binflow. */
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <fstream>
#include <memory>

class FileReader
{
public:
    static std::unique_ptr<std::vector<uint8_t>> ReadFile(const std::string& Path);
};
