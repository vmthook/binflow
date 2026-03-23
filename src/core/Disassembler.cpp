/* @author vmthook - Disassembly engine for binflow using Zydis. */
#include <Disassembler.hpp>
#include <Zydis/Zydis.h>
#include <cstring>

std::vector<Instruction> Disassembler::Disassemble(const std::vector<uint8_t>& Data, uint64_t Start, size_t Length)
{
    std::vector<Instruction> Instructions;

    ZydisDecoder Decoder;
    ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter Formatter;
    ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisDecodedInstruction DecodedInstruction;
    ZydisDecodedOperand DecodedOperands[ZYDIS_MAX_OPERAND_COUNT];

    size_t Offset = Start;
    while (Offset < Start + Length)
    {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Data.data() + Offset, Length - (Offset - Start), &DecodedInstruction, DecodedOperands)))
        {
            char Buffer[256];
            ZydisFormatterFormatInstruction(&Formatter, &DecodedInstruction, DecodedOperands, DecodedInstruction.operand_count_visible, Buffer, sizeof(Buffer), Offset, nullptr);

            Instruction Entry;
            Entry.Address = Offset;
            Entry.Text = std::string(Buffer);
            Entry.Mnemonic = std::string(ZydisMnemonicGetString(DecodedInstruction.mnemonic));
            Entry.Category = std::string(ZydisCategoryGetString(DecodedInstruction.meta.category));
            Entry.Size = DecodedInstruction.length;
            Entry.IsCall = (DecodedInstruction.meta.category == ZYDIS_CATEGORY_CALL);
            Entry.IsJump = (DecodedInstruction.meta.category == ZYDIS_CATEGORY_COND_BR || DecodedInstruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
            Entry.Target = 0;

            if (Entry.IsCall || Entry.IsJump)
            {
                ZydisCalcAbsoluteAddress(&DecodedInstruction, &DecodedOperands[0], Offset, &Entry.Target);
            }

            std::memcpy(Entry.RawBytes, Data.data() + Offset, DecodedInstruction.length);

            Instructions.push_back(Entry);
            Offset += DecodedInstruction.length;
        }
        else
        {
            Offset++;
        }
    }

    return Instructions;
}
