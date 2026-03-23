/* @author vmthook - Advanced analysis engine for binflow. */
#include <Analyzer.hpp>
#include <set>
#include <map>
#include <queue>
#include <algorithm>
#include <unordered_set>

void Analyzer::Analyze(const std::vector<Instruction>& Instructions)
{
    for (size_t i = 0; i < Instructions.size(); ++i)
    {
        const auto& Entry = Instructions[i];
        if (Entry.IsCall && Entry.Target != 0) Candidates.insert(Entry.Target);
        if (Entry.Text.find("push rbp") != std::string::npos)
        {
            if (i + 1 < Instructions.size() && Instructions[i + 1].Text.find("mov rbp, rsp") != std::string::npos)
                Candidates.insert(Entry.Address);
        }
    }
}

std::unordered_set<uint64_t> Analyzer::GetFunctionCandidates()
{
    return Candidates;
}

std::vector<SecurityFinding> Analyzer::ScanSecurity(const std::vector<Instruction>& Instructions, const std::map<uint64_t, std::string>& ImportMap)
{
    std::vector<SecurityFinding> Findings;
    for (const auto& Inst : Instructions)
    {
        if (Inst.IsCall && ImportMap.count(Inst.Target))
        {
            std::string Name = ImportMap.at(Inst.Target);
            if (Name.find("Debugger") != std::string::npos || Name.find("NtQuery") != std::string::npos)
                Findings.push_back({ Inst.Address, "ANTI-DEBUG", "Critical API reference found: " + Name });
        }
        if (Inst.Mnemonic == "rdtsc") Findings.push_back({ Inst.Address, "ANTI-VM", "Timing check (RDTSC)" });
        if (Inst.Mnemonic == "cpuid") Findings.push_back({ Inst.Address, "ANTI-VM", "Hardware info check (CPUID)" });
        if (Inst.Mnemonic == "syscall") Findings.push_back({ Inst.Address, "SYSCALL", "Direct NT kernel transition found" });
    }
    return Findings;
}

std::string Analyzer::MapSyscall(uint32_t Number)
{
    static std::map<uint32_t, std::string> Map = {
        {0x01, "NtRegisterClassView"}, {0x18, "NtWriteFile"}, {0x3F, "NtCreateFile"},
        {0x55, "NtCreateProcess"}, {0x10, "NtQueryInformationProcess"}, {0x2C, "NtOpenProcess"},
        {0x33, "NtAllocateVirtualMemory"}, {0x3A, "NtProtectVirtualMemory"}
    };
    return Map.count(Number) ? Map[Number] : "UNKNOWN";
}

std::vector<Edge> Analyzer::GetJumps()
{
    return FlowEdges;
}

std::vector<BasicBlock> Analyzer::GetBasicBlocks(const std::vector<Instruction>& Instructions, const std::map<uint64_t, std::string>& StringMap, uint64_t EntryPoint)
{
    std::vector<BasicBlock> Blocks;
    if (Instructions.empty()) return Blocks;

    std::set<uint64_t> Leaders;
    Leaders.insert(Instructions[0].Address);
    if (EntryPoint != 0) Leaders.insert(EntryPoint);

    for (size_t i = 0; i < Instructions.size(); ++i)
    {
        if (Instructions[i].IsJump || Instructions[i].IsCall || Instructions[i].Mnemonic == "ret")
        {
            if (Instructions[i].Target != 0) Leaders.insert(Instructions[i].Target);
            if (i + 1 < Instructions.size()) Leaders.insert(Instructions[i + 1].Address);
        }
    }

    BasicBlock Current = { 0, 0, {}, "", "DATA", 0.0, {}, "", {}, false };
    bool Started = false; int InstCount = 0; std::map<std::string, int> Categories;

    for (size_t i = 0; i < Instructions.size(); ++i)
    {
        const auto& Inst = Instructions[i];
        if (Leaders.count(Inst.Address))
        {
            if (Started)
            {
                std::string TopCat = "DATA"; int MaxC = 0;
                for (auto const& [C, V] : Categories) { if (V > MaxC) { MaxC = V; TopCat = C; } }
                Current.Category = TopCat;
                Blocks.push_back(Current);
            }
            Current = { Inst.Address, 0, {}, "", "DATA", 0.0, {}, "", {}, false };
            InstCount = 0; Categories.clear(); Started = true;
        }

        Current.End = Inst.Address;
        if (InstCount < 4) { Current.Summary += Inst.Text + "\n"; InstCount++; }
        Categories[Inst.Category]++;

        if (InstCount == 1)
        {
            if (Inst.Text.find("push rbp") != std::string::npos || Inst.Text.find("sub rsp") != std::string::npos) Current.CustomLabel = "[PROLOGUE]";
            else if (Inst.Text.find("pop rbp") != std::string::npos || Inst.Mnemonic == "ret") Current.CustomLabel = "[EPILOGUE]";
        }

        if (Inst.Mnemonic == "syscall" && i > 0 && Instructions[i-1].Mnemonic == "mov") Current.Tags.push_back("SYSCALL: " + MapSyscall(0x18));
        if (Inst.Mnemonic == "jmp" && Inst.Text.find("[") != std::string::npos) Current.Tags.push_back("INDIRECT_JUMP_TABLE");
        if (StringMap.count(Inst.Target)) Current.XRefs.push_back(StringMap.at(Inst.Target));

        bool IsRet = (Inst.Mnemonic == "ret");
        bool IsUncond = (Inst.Mnemonic == "jmp");
        if (Inst.IsJump || Inst.IsCall) { if (Inst.Target != 0) Current.Successors.push_back(Inst.Target); }
        if (i + 1 < Instructions.size() && Leaders.count(Instructions[i + 1].Address) && !IsRet && !IsUncond)
            Current.Successors.push_back(Instructions[i + 1].Address);
    }
    if (Started) Blocks.push_back(Current);

    std::map<uint64_t, int> InDegree;
    for (const auto& B : Blocks) { for (uint64_t S : B.Successors) InDegree[S]++; }
    for (auto& B : Blocks) { if (InDegree[B.Start] > 5) B.Tags.push_back("CFF_DISPATCHER_CANDIDATE"); }

    std::queue<uint64_t> Q; std::unordered_set<uint64_t> Reachable;
    uint64_t StartAddr = (EntryPoint != 0) ? EntryPoint : Blocks[0].Start;
    Q.push(StartAddr); Reachable.insert(StartAddr);
    std::map<uint64_t, BasicBlock*> Map; for (auto& B : Blocks) Map[B.Start] = &B;

    while (!Q.empty())
    {
        uint64_t A = Q.front(); Q.pop();
        if (Map.count(A))
        {
            Map[A]->IsReachable = true;
            for (uint64_t S : Map[A]->Successors) if (Reachable.find(S) == Reachable.end()) { Reachable.insert(S); Q.push(S); }
        }
    }
    return Blocks;
}

std::vector<CallGraphEntry> Analyzer::GetCallGraph(const std::vector<Instruction>& Instructions, const std::vector<uint64_t>& Functions)
{
    std::vector<CallGraphEntry> Result;
    std::set<uint64_t> FuncSet(Functions.begin(), Functions.end());
    std::map<uint64_t, std::vector<uint64_t>> CallMap; uint64_t CurrentFunc = 0;
    for (const auto& Inst : Instructions)
    {
        if (FuncSet.count(Inst.Address)) CurrentFunc = Inst.Address;
        if (CurrentFunc != 0 && Inst.IsCall && Inst.Target != 0) CallMap[CurrentFunc].push_back(Inst.Target);
    }
    for (auto const& [K, V] : CallMap) Result.push_back({ K, V });
    return Result;
}
