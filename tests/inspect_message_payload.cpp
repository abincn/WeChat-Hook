// Offline normalization of recorded fixtures only. No native source, sockets,
// event injection or sends. Keep raw evidence local; write projections to disk.
#include "wxcx_message_model.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace wxcx::messages;
int main(int argc, char** argv) {
    try {
        if (argc != 3 || std::filesystem::file_size(argv[1]) > 16 * 1024 * 1024)
            throw std::invalid_argument("Usage: inspect_message_payload INPUT_JSON OUTPUT_JSON (max 16 MiB)");
        std::ifstream input(argv[1], std::ios::binary); Json records; input >> records;
        if (!records.is_array() || records.size() > 128) throw std::invalid_argument("Expected bounded fixture array");
        Json output = Json::array();
        for (const auto& record : records) {
            Input message;
            message.from = record.value("from", ""); message.to = record.value("to", "");
            message.self_wxid = record.value("self_id", ""); message.type = record.at("type").get<uint32_t>();
            message.content = record.at("content").get<std::string>();
            message.content_complete = record.value("content_complete", true);
            message.msgsource = record.value("msgsource", "");
            message.msgsource_known = record.value("msgsource_known", false);
            output.push_back({{"fixture_id", record.at("fixture_id")}, {"normalized", Normalize(message)}});
        }
        std::ofstream result(argv[2], std::ios::binary); result << output.dump(2); result.close();
        if (!result) throw std::runtime_error("Could not save projection");
        std::cout << "Normalized " << output.size() << " recorded fixtures offline; no publication or sends.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
