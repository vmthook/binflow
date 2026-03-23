/* @author vmthook - Advanced analysis engine for binflow. */
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <unordered_set>
#include <map>
#include "Disassembler.hpp"

struct SecurityFinding
{
    uint64_t Address;
    std::string Type;
    std::string Description;
};

struct Edge
{
    uint64_t From;
    uint64_t To;
    bool IsConditional;
    bool IsTaken;
};

struct BasicBlock
{
    uint64_t Start;
    uint64_t End;
    std::vector<uint64_t> Successors;
    std::string Summary;
    std::string Category;
    double AvgEntropy;
    std::vector<std::string> XRefs;
    std::string CustomLabel;
    std::vector<std::string> Tags;
    bool IsReachable;
};

struct CallGraphEntry
{
    uint64_t Caller;
    std::vector<uint64_t> Callees;
};

class Analyzer
{
public:
    void Analyze(const std::vector<Instruction>& Instructions);
    std::vector<SecurityFinding> ScanSecurity(const std::vector<Instruction>& Instructions, const std::map<uint64_t, std::string>& ImportMap);
    std::unordered_set<uint64_t> GetFunctionCandidates();
    std::vector<Edge> GetJumps();
    std::vector<BasicBlock> GetBasicBlocks(const std::vector<Instruction>& Instructions, const std::map<uint64_t, std::string>& StringMap, uint64_t EntryPoint = 0);
    std::vector<CallGraphEntry> GetCallGraph(const std::vector<Instruction>& Instructions, const std::vector<uint64_t>& Functions);
    std::string MapSyscall(uint32_t Number);

private:
    std::unordered_set<uint64_t> Candidates;
    std::vector<Edge> FlowEdges;
};
