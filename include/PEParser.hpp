/* @author vmthook - Portable Executable parser for binflow. */
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <cmath>
#include <map>

struct SectionInfo
{
    std::string Name;
    uint32_t VirtualAddress;
    uint32_t VirtualSize;
    uint32_t RawAddress;
    uint32_t RawSize;
    uint32_t Characteristics;
    bool IsExecutable;
    bool IsWritable;
    double Entropy;
};

struct ImportEntry
{
    std::string Library;
    std::string Function;
    uint32_t Hint;
    uint32_t Address;
};

struct StringEntry
{
    std::string Content;
    std::string Category;
    uint32_t Address;
};

class PEParser
{
public:
    bool Parse(const std::vector<uint8_t>& Data);
    uint32_t GetEntryPoint();
    std::vector<SectionInfo> GetSections();
    std::vector<ImportEntry> GetImports();
    std::vector<StringEntry> GetStringsEx();
    uint32_t GetTimestamp();
    std::string GetMachine();
    double CalculateEntropy(uint32_t Offset, uint32_t Size);

private:
    const std::vector<uint8_t>* DataPtr;
};
