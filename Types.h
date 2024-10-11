#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

using bytes_32_t = std::array<uint8_t, 32>;
using bytes_span_32_t = std::span<uint8_t, 32>;
using bytes_span_32_c_t = std::span<uint8_t const, 32>;

using bytes_16_t = std::array<uint8_t, 16>;
using bytes_span_16_t = std::span<uint8_t, 16>;
using bytes_span_16_c_t = std::span<uint8_t const, 16>;

using bytes_span_t = std::span<uint8_t>;
using bytes_span_c_t = std::span<uint8_t const>;
using bytes_t = std::vector<uint8_t>;
