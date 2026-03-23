/* @author vmthook - Professional formatting for binflow output. */
#include <Formatter.hpp>
#include <iostream>

void Formatter::SaveLog(const std::string& FileName, const nlohmann::ordered_json& LogData)
{
    std::ofstream File(FileName);
    if (File.is_open())
    {
        File << LogData.dump(4);
    }

    std::cout << "Done! Log saved to: " << FileName << std::endl;
}
