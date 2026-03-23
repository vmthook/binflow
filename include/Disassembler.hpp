/* @author vmthook - Disassembly engine for binflow using Zydis. */
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <memory>

struct Instruction
{
    uint64_t Address;
    std::string Text;
    std::string Mnemonic;
    std::string Category;
    uint8_t Size;
    bool IsCall;
    bool IsJump;
    uint64_t Target;
    uint8_t RawBytes[15];
};

class Disassembler
{
public:
    std::vector<Instruction> Disassemble(const std::vector<uint8_t>& Data, uint64_t Start, size_t Length);
};
