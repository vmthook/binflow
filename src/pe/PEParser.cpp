/* @author vmthook - Portable Executable parser for binflow. */
#include <PEParser.hpp>
#include <windows.h>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <map>
#include <cmath>

bool PEParser::Parse(const std::vector<uint8_t>& Data)
{
    if (Data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(Data.data());
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(Data.data() + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE) return false;
    DataPtr = &Data;
    return true;
}

std::vector<SectionInfo> PEParser::GetSections()
{
    std::vector<SectionInfo> List;
    const auto DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(DataPtr->data());
    const auto NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(DataPtr->data() + DosHeader->e_lfanew);
    const auto SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i)
    {
        SectionInfo Entry;
        Entry.Name = std::string(reinterpret_cast<const char*>(SectionHeader[i].Name), 8);
        Entry.Name.erase(std::find(Entry.Name.begin(), Entry.Name.end(), '\0'), Entry.Name.end());
        Entry.VirtualAddress = SectionHeader[i].VirtualAddress;
        Entry.VirtualSize = SectionHeader[i].Misc.VirtualSize;
        Entry.RawAddress = SectionHeader[i].PointerToRawData;
        Entry.RawSize = SectionHeader[i].SizeOfRawData;
        Entry.IsExecutable = (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
        Entry.IsWritable = (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE);
        Entry.Entropy = CalculateEntropy(Entry.RawAddress, Entry.RawSize);
        List.push_back(Entry);
    }
    return List;
}

uint32_t PEParser::GetEntryPoint()
{
    const auto DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(DataPtr->data());
    const auto NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(DataPtr->data() + DosHeader->e_lfanew);
    return NtHeader->OptionalHeader.AddressOfEntryPoint;
}

std::vector<ImportEntry> PEParser::GetImports()
{
    std::vector<ImportEntry> ImportsList;
    const auto DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(DataPtr->data());
    const auto NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(DataPtr->data() + DosHeader->e_lfanew);
    const auto ImportDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (ImportDirectory.Size == 0) return ImportsList;
    auto RvaToOffset = [&](uint32_t Rva) -> uint32_t
    {
        const auto FirstSection = IMAGE_FIRST_SECTION(NtHeader);
        for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i)
        {
            if (Rva >= FirstSection[i].VirtualAddress && Rva < FirstSection[i].VirtualAddress + FirstSection[i].Misc.VirtualSize)
                return FirstSection[i].PointerToRawData + (Rva - FirstSection[i].VirtualAddress);
        }
        return 0;
    };
    uint32_t ImportOffset = RvaToOffset(ImportDirectory.VirtualAddress);
    if (ImportOffset == 0) return ImportsList;
    auto Descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(DataPtr->data() + ImportOffset);
    while (Descriptor->Name != 0)
    {
        uint32_t NameOffset = RvaToOffset(Descriptor->Name);
        std::string LibName(reinterpret_cast<const char*>(DataPtr->data() + NameOffset));
        uint32_t IatRva = Descriptor->FirstThunk;
        uint32_t OriginalThunkRva = Descriptor->OriginalFirstThunk == 0 ? Descriptor->FirstThunk : Descriptor->OriginalFirstThunk;
        uint32_t ThunkOffset = RvaToOffset(OriginalThunkRva);
        int ThunkIdx = 0;
        if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            auto Thunk = reinterpret_cast<const uint64_t*>(DataPtr->data() + ThunkOffset);
            while (*Thunk != 0)
            {
                if (!(*Thunk & 0x8000000000000000))
                {
                    uint32_t NameAddr = RvaToOffset(static_cast<uint32_t>(*Thunk)) + 2;
                    if (NameAddr > 2 && NameAddr < DataPtr->size())
                        ImportsList.push_back({ LibName, (const char*)(DataPtr->data() + NameAddr), 0, (uint32_t)(IatRva + ThunkIdx * 8) });
                }
                Thunk++; ThunkIdx++;
            }
        }
        else
        {
            auto Thunk = reinterpret_cast<const uint32_t*>(DataPtr->data() + ThunkOffset);
            while (*Thunk != 0)
            {
                if (!(*Thunk & 0x80000000))
                {
                    uint32_t NameAddr = RvaToOffset(*Thunk) + 2;
                    if (NameAddr > 2 && NameAddr < DataPtr->size())
                        ImportsList.push_back({ LibName, (const char*)(DataPtr->data() + NameAddr), 0, (uint32_t)(IatRva + ThunkIdx * 4) });
                }
                Thunk++; ThunkIdx++;
            }
        }
        Descriptor++;
    }
    return ImportsList;
}

std::vector<StringEntry> PEParser::GetStringsEx()
{
    std::vector<StringEntry> List;
    std::string Current;
    uint32_t StartOffset = 0;
    for (uint32_t i = 0; i < DataPtr->size(); ++i)
    {
        uint8_t Byte = (*DataPtr)[i];
        if (std::isprint(Byte)) { if (Current.empty()) StartOffset = i; Current += static_cast<char>(Byte); }
        else
        {
            if (Current.size() >= 5)
            {
                std::string Cat = "GENERAL";
                std::string Low = Current; std::transform(Low.begin(), Low.end(), Low.begin(), ::tolower);
                if (Low.find("http") != std::string::npos || Low.find(".com") != std::string::npos) Cat = "NETWORK";
                else if (Low.find("hkey") != std::string::npos || Low.find("software\\") != std::string::npos) Cat = "REGISTRY";
                else if (Low.find("windows\\") != std::string::npos || Low.find("c:\\") != std::string::npos) Cat = "FILESYSTEM";
                else if (Low.find("debugger") != std::string::npos || Low.find("query") != std::string::npos) Cat = "SECURITY";
                List.push_back({ Current, Cat, StartOffset });
            }
            Current.clear();
        }
    }
    return List;
}

uint32_t PEParser::GetTimestamp()
{
    const auto DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(DataPtr->data());
    const auto NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(DataPtr->data() + DosHeader->e_lfanew);
    return NtHeader->FileHeader.TimeDateStamp;
}

std::string PEParser::GetMachine()
{
    const auto DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(DataPtr->data());
    const auto NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(DataPtr->data() + DosHeader->e_lfanew);
    if (NtHeader->FileHeader.Machine == 0x8664) return "AMD64";
    if (NtHeader->FileHeader.Machine == 0x014c) return "I386";
    return "UNKNOWN";
}

double PEParser::CalculateEntropy(uint32_t Offset, uint32_t Size)
{
    if (Size == 0 || Offset + Size > DataPtr->size()) return 0.0;
    std::map<uint8_t, uint32_t> Counts;
    for (uint32_t i = 0; i < Size; ++i) Counts[(*DataPtr)[Offset + i]]++;
    double Entropy = 0.0;
    for (auto const& [Byte, Count] : Counts)
    {
        double Prob = static_cast<double>(Count) / Size;
        if (Prob > 0) Entropy -= Prob * (std::log(Prob) / std::log(2));
    }
    return Entropy;
}
