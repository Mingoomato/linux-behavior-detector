#include "bdetect/json.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t max_fuzz_input = 1024U * 1024U;
    if (size > max_fuzz_input) return 0;
    std::string input;
    if (size != 0U)
        input.assign(reinterpret_cast<const char *>(data), size);
    try {
        (void)bdetect::json::Parser(input, max_fuzz_input).parse();
    } catch (const std::exception &) {
        // Malformed JSON is an expected parser result; sanitizer failures remain visible.
    }
    return 0;
}
