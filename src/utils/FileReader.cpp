/* @author vmthook - Basic file reading utilities for binflow. */
#include <FileReader.hpp>

std::unique_ptr<std::vector<uint8_t>> FileReader::ReadFile(const std::string& Path)
{
    std::ifstream File(Path, std::ios::binary | std::ios::ate);
    if (!File.is_open())
    {
        return nullptr;
    }

    std::streamsize Size = File.tellg();
    File.seekg(0, std::ios::beg);

    auto Buffer = std::make_unique<std::vector<uint8_t>>(Size);
    if (File.read(reinterpret_cast<char*>(Buffer->data()), Size))
    {
        return Buffer;
    }

    return nullptr;
}
