/* @author vmthook - Main entry point for binflow. */
#include <iostream>
#include <vector>
#include <memory>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include <FileReader.hpp>
#include <PEParser.hpp>
#include <Disassembler.hpp>
#include <Analyzer.hpp>
#include <Formatter.hpp>
#include <CLI.hpp>
#include <Visualizer.hpp>

using json = nlohmann::ordered_json;

int main(int Argc, char* Argv[])
{
    if (!CLI::Parse(Argc, Argv))
    {
        std::cout << "Usage: binflow.exe <path_to_binary> [--entry] [--functions] [--full]" << std::endl;
        std::cout << "Press ENTER to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    std::string BinaryPath = CLI::GetPath();
    auto BinaryData = FileReader::ReadFile(BinaryPath);
    if (!BinaryData) return 1;

    PEParser Parser;
    if (!Parser.Parse(*BinaryData)) return 1;

    auto Sections = Parser.GetSections();
    auto EntryRva = Parser.GetEntryPoint();
    auto Imports = Parser.GetImports();
    auto StringsEx = Parser.GetStringsEx();

    std::map<uint64_t, std::string> ImportMap;
    std::map<uint64_t, std::string> StringTable;
    for (const auto& Imp : Imports) ImportMap[Imp.Address] = Imp.Function;
    for (const auto& Str : StringsEx) StringTable[Str.Address] = Str.Content;

    uint32_t TextOffset = 0, TextSize = 0;
    uint64_t EntryRaw = 0;
    for (const auto& Sec : Sections)
    {
        if (Sec.Name.find(".text") != std::string::npos) { TextOffset = Sec.RawAddress; TextSize = Sec.RawSize; }
        if (EntryRva >= Sec.VirtualAddress && EntryRva < Sec.VirtualAddress + Sec.VirtualSize)
            EntryRaw = Sec.RawAddress + (EntryRva - Sec.VirtualAddress);
    }

    Disassembler Disasm;
    auto Instructions = Disasm.Disassemble(*BinaryData, TextOffset, TextSize);

    Analyzer BinAnalyzer;
    BinAnalyzer.Analyze(Instructions);

    auto FunctionsSet = BinAnalyzer.GetFunctionCandidates();
    std::vector<uint64_t> Functions(FunctionsSet.begin(), FunctionsSet.end());
    std::sort(Functions.begin(), Functions.end());
    auto Blocks = BinAnalyzer.GetBasicBlocks(Instructions, StringTable, EntryRaw);
    auto CallGraph = BinAnalyzer.GetCallGraph(Instructions, Functions);
    auto SecurityAudit = BinAnalyzer.ScanSecurity(Instructions, ImportMap);

    json Log;
    Log["binary_info"] = {
        {"file", BinaryPath}, {"machine", Parser.GetMachine()}, {"timestamp", Parser.GetTimestamp()}, {"entry_point", EntryRva}
    };

    for (const auto& Finding : SecurityAudit)
        Log["security_audit"].push_back({ {"address", Finding.Address}, {"type", Finding.Type}, {"description", Finding.Description} });

    for (const auto& Entry : CallGraph) Log["binary_info"]["call_graph"].push_back({ {"caller", Entry.Caller}, {"callees", Entry.Callees} });

    for (const auto& Sec : Sections)
        Log["sections"].push_back({ {"name", Sec.Name}, {"v_addr", Sec.VirtualAddress}, {"v_size", Sec.VirtualSize}, {"r_addr", Sec.RawAddress}, {"r_size", Sec.RawSize}, {"entropy", Sec.Entropy} });

    for (const auto& Imp : Imports) Log["imports"].push_back({ {"library", Imp.Library}, {"function", Imp.Function}, {"address", Imp.Address} });

    for (const auto& Str : StringsEx) Log["strings_categorized"].push_back({ {"content", Str.Content}, {"category", Str.Category}, {"address", Str.Address} });

    for (const auto& Block : Blocks)
    {
        json B = { {"start", Block.Start}, {"end", Block.End}, {"successors", Block.Successors}, {"category", Block.Category}, {"reachable", Block.IsReachable} };
        if (!Block.CustomLabel.empty()) B["label"] = Block.CustomLabel;
        if (!Block.Tags.empty()) B["tags"] = Block.Tags;
        if (!Block.XRefs.empty()) B["strings"] = Block.XRefs;
        Log["basic_blocks"].push_back(B);
    }

    std::string BaseName = BinaryPath.substr(BinaryPath.find_last_of("\\/") + 1);
    Formatter::SaveLog(BaseName + "_log.json", Log);
    Visualizer::GenerateFlowGraph(BaseName + "_flow.png", Blocks, EntryRaw, ImportMap, SecurityAudit);

    return 0;
}
