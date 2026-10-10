#ifndef BDETECT_JSON_HPP
#define BDETECT_JSON_HPP

#include <cctype>
#include <cstddef>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace bdetect::json {
struct Value;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;
struct Value {
    std::variant<std::nullptr_t, bool, double, std::string, Array, Object> data;
    const Value *get(std::string key) const {
        const auto *o = std::get_if<Object>(&data);
        if (!o) return nullptr;
        const auto it = o->find(key);
        return it == o->end() ? nullptr : &it->second;
    }
    std::string string_or(const std::string &fallback = {}) const {
        const auto *s = std::get_if<std::string>(&data);
        return s ? *s : fallback;
    }
    double number_or(double fallback = 0) const {
        const auto *n = std::get_if<double>(&data);
        return n ? *n : fallback;
    }
};

class Parser {
public:
    explicit Parser(const std::string &input, std::size_t max_bytes = 1024U * 1024U) : input_(input) {
        if (input.size() > max_bytes) throw std::runtime_error("JSON record too large");
    }
    Value parse() {
        Value v = value(0);
        ws();
        if (pos_ != input_.size()) throw std::runtime_error("trailing JSON data");
        return v;
    }
private:
    const std::string &input_;
    std::size_t pos_ = 0;
    void ws() { while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_]))) ++pos_; }
    char take() { if (pos_ >= input_.size()) throw std::runtime_error("unexpected end of JSON"); return input_[pos_++]; }
    bool eat(char c) { ws(); if (pos_ < input_.size() && input_[pos_] == c) { ++pos_; return true; } return false; }
    unsigned hex4() {
        unsigned code = 0;
        for (int i = 0; i < 4; ++i) {
            const char h = take();
            code <<= 4U;
            if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
            else throw std::runtime_error("invalid unicode escape");
        }
        return code;
    }
    static void append_utf8(std::string &out, unsigned code) {
        if (code < 0x80U) out.push_back(static_cast<char>(code));
        else if (code < 0x800U) {
            out.push_back(static_cast<char>(0xc0U | (code >> 6U)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
        } else if (code < 0x10000U) {
            out.push_back(static_cast<char>(0xe0U | (code >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xf0U | (code >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((code >> 12U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
        }
    }
    std::string string() {
        ws();
        if (take() != '"') throw std::runtime_error("expected JSON string");
        std::string out;
        while (pos_ < input_.size()) {
            unsigned char c = static_cast<unsigned char>(take());
            if (c == '"') return out;
            if (c < 0x20U) throw std::runtime_error("control byte in JSON string");
            if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
            char esc = take();
            switch (esc) {
            case '"': out.push_back('"'); break; case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break; case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break;
            case 'u': {
                unsigned code = hex4();
                if (code >= 0xd800U && code <= 0xdbffU) {
                    if (take() != '\\' || take() != 'u')
                        throw std::runtime_error("unpaired high surrogate");
                    const unsigned low = hex4();
                    if (low < 0xdc00U || low > 0xdfffU)
                        throw std::runtime_error("invalid low surrogate");
                    code = 0x10000U + ((code - 0xd800U) << 10U) + (low - 0xdc00U);
                } else if (code >= 0xdc00U && code <= 0xdfffU) {
                    throw std::runtime_error("unpaired low surrogate");
                }
                append_utf8(out, code);
                break;
            }
            default: throw std::runtime_error("invalid JSON escape");
            }
        }
        throw std::runtime_error("unterminated JSON string");
    }
    Value value(unsigned depth) {
        if (depth > 32U) throw std::runtime_error("JSON nesting limit");
        ws();
        if (pos_ >= input_.size()) throw std::runtime_error("missing JSON value");
        char c = input_[pos_];
        if (c == '"') return Value{string()};
        if (c == '{') {
            ++pos_; Object obj; ws();
            if (eat('}')) return Value{obj};
            do {
                std::string key = string();
                if (!eat(':')) throw std::runtime_error("expected colon");
                if (!obj.emplace(key, value(depth + 1U)).second) throw std::runtime_error("duplicate object key");
                ws();
                if (eat('}')) break;
                if (!eat(',')) throw std::runtime_error("expected comma");
            } while (true);
            return Value{obj};
        }
        if (c == '[') {
            ++pos_; Array arr; ws();
            if (eat(']')) return Value{arr};
            do {
                arr.push_back(value(depth + 1U)); ws();
                if (eat(']')) break;
                if (!eat(',')) throw std::runtime_error("expected comma");
            } while (true);
            return Value{arr};
        }
        if (input_.compare(pos_, 4, "true") == 0) { pos_ += 4; return Value{true}; }
        if (input_.compare(pos_, 5, "false") == 0) { pos_ += 5; return Value{false}; }
        if (input_.compare(pos_, 4, "null") == 0) { pos_ += 4; return Value{nullptr}; }
        const std::size_t start = pos_;
        if (input_[pos_] == '-') ++pos_;
        if (pos_ >= input_.size()) throw std::runtime_error("invalid JSON number");
        if (input_[pos_] == '0') {
            ++pos_;
        } else if (input_[pos_] >= '1' && input_[pos_] <= '9') {
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
        } else {
            throw std::runtime_error("invalid JSON number");
        }
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            const std::size_t fraction_start = pos_;
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
            if (pos_ == fraction_start) throw std::runtime_error("invalid JSON number");
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) ++pos_;
            const std::size_t exponent_start = pos_;
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
            if (pos_ == exponent_start) throw std::runtime_error("invalid JSON number");
        }
        const std::string token = input_.substr(start, pos_ - start);
        char *end = nullptr;
        errno = 0;
        const double n = std::strtod(token.c_str(), &end);
        if (errno == ERANGE || end != token.c_str() + token.size() || !std::isfinite(n))
            throw std::runtime_error("invalid JSON number");
        return Value{n};
    }
};
} // namespace bdetect::json

#endif
