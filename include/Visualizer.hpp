/* @author vmthook - Graph visualization for binflow. */
#pragma once
#include <vector>
#include <string>
#include <map>
#include "Analyzer.hpp"

class Visualizer
{
public:
    static void GenerateFlowGraph(const std::string& FileName, const std::vector<BasicBlock>& Blocks, uint64_t EntryPoint = 0, const std::map<uint64_t, std::string>& ImportMap = {}, const std::vector<SecurityFinding>& Findings = {});
};
