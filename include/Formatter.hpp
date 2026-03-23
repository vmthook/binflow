/* @author vmthook - Professional formatting for binflow output. */
#pragma once
#include <vector>
#include <iomanip>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>
#include "Disassembler.hpp"
#include "Analyzer.hpp"
#include "PEParser.hpp"

class Formatter
{
public:
    static void SaveLog(const std::string& FileName, const nlohmann::ordered_json& LogData);
};
