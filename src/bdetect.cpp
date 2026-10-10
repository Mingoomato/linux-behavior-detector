#include "bdetect/json.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using bdetect::json::Value;
constexpr std::size_t MAX_RECORD_BYTES = 1024U * 1024U;
constexpr std::size_t MAX_DECISION_RECORD_BYTES = 64U * 1024U * 1024U;
constexpr std::uintmax_t MAX_INPUT_FILE_BYTES = 512U * 1024U * 1024U;
constexpr std::size_t MAX_EVENT_COUNT = 1000000U;
constexpr std::size_t MAX_LABEL_COUNT = 100000U;
constexpr std::size_t MAX_LABEL_FIELD_BYTES = 256U;
constexpr std::size_t MAX_RULE_PAIR_UPDATES = 10000000U;
struct Event {
    std::string id, source, host, kind, path, observed, coverage, content_hash;
    std::string producer_session_id;
    std::uint64_t producer_sequence = 0;
    bool has_producer_sequence = false;
    std::int64_t epoch = 0;
};
struct Rule {
    std::string id, feature, op;
    int threshold = 0, weight = 0, min_samples = 1;
};
struct Rules {
    std::string revision = "baseline-1";
    int window = 30, lateness_ms = 2000, max_entities = 10000;
    int min_events = 10, cutoff = 60;
    std::string sha256;
    std::vector<Rule> rules;
};
struct Reason {
    std::string rule_id, feature, op;
    int observed = 0, threshold = 0, weight = 0, contribution = 0;
    std::vector<std::string> source_event_ids;
};
struct Decision {
    std::string id, host, label, start, end;
    int score = 0;
    std::vector<Reason> reasons;
    std::vector<std::string> event_ids;
    std::vector<std::string> unknown;
};

std::string sha256(std::string_view data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("SHA-256 calculation failed");
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < size; ++i) out << std::setw(2) << static_cast<unsigned>(digest[i]);
    return out.str();
}

std::string sha256_file(const std::string &path) {
    using Ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Ctx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("SHA-256 initialization failed");
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open input for hashing: " + path);
    std::array<char, 65536> buffer{};
    std::uintmax_t total_bytes = 0;
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = in.gcount();
        if (count > 0) {
            const auto bytes = static_cast<std::uintmax_t>(count);
            if (bytes > MAX_INPUT_FILE_BYTES - total_bytes)
                throw std::runtime_error("input file exceeds 512 MiB hashing limit");
            total_bytes += bytes;
            if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<std::size_t>(count)) != 1)
                throw std::runtime_error("SHA-256 update failed");
        }
    }
    if (in.bad()) throw std::runtime_error("input read failure while hashing");
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &size) != 1)
        throw std::runtime_error("SHA-256 finalization failed");
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < size; ++i) out << std::setw(2) << static_cast<unsigned>(digest[i]);
    return out.str();
}

std::string escape(const std::string &s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') o << '\\' << static_cast<char>(c);
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c < 0x20U) {
            static constexpr char hex[] = "0123456789abcdef";
            o << "\\u00" << hex[c >> 4U] << hex[c & 0x0fU];
        }
        else o << static_cast<char>(c);
    }
    return o.str();
}

std::size_t encoded_string_size(const std::string &value) {
    std::size_t size = 2U;
    for (unsigned char c : value) {
        const std::size_t extra = c == '"' || c == '\\' || c == '\n' || c == '\r' ||
            c == '\t' || c == '\b' || c == '\f' ? 2U : c < 0x20U ? 6U : 1U;
        size += extra;
    }
    return size;
}

const Value &required(const Value &v, const char *key) {
    const Value *p = v.get(key);
    if (!p) throw std::runtime_error(std::string("missing field: ") + key);
    return *p;
}

const bdetect::json::Object &object_value(const Value &v, const char *field) {
    const auto *object = std::get_if<bdetect::json::Object>(&v.data);
    if (!object) throw std::runtime_error(std::string("field must be an object: ") + field);
    return *object;
}

std::string required_text(const Value &v, const char *field) {
    const Value &value = required(v, field);
    const auto *text = std::get_if<std::string>(&value.data);
    if (!text) throw std::runtime_error(std::string("field must be a string: ") + field);
    return *text;
}

void validate_nullable_integer(const Value &object, const char *field) {
    const Value &value = required(object, field);
    if (std::holds_alternative<std::nullptr_t>(value.data)) return;
    const double *number = std::get_if<double>(&value.data);
    if (!number || !std::isfinite(*number) || std::floor(*number) != *number ||
        *number < 0 || *number > 9007199254740991.0)
        throw std::runtime_error(std::string("field must be null or a nonnegative integer: ") + field);
}

void validate_optional_integer(const Value &object, const char *field) {
    const Value *value = object.get(field);
    if (!value) return;
    const double *number = std::get_if<double>(&value->data);
    if (!number || !std::isfinite(*number) || std::floor(*number) != *number ||
        *number < 0 || *number > 9007199254740991.0)
        throw std::runtime_error(std::string("field must be a nonnegative integer: ") + field);
}

bool read_csv_record(std::istream &in, std::vector<std::string> &fields,
                    std::size_t &line_number, std::size_t &start_line) {
    fields.clear();
    std::string field;
    std::size_t record_bytes = 0;
    start_line = line_number;
    bool consumed = false;
    bool quoted = false;
    bool after_quote = false;
    bool field_started = false;
    auto add_byte = [&record_bytes]() {
        if (++record_bytes > MAX_RECORD_BYTES)
            throw std::runtime_error("CSV record too large");
    };
    auto append = [&field](char value) {
        if (field.size() == MAX_LABEL_FIELD_BYTES)
            throw std::runtime_error("CSV field too large");
        field.push_back(value);
    };
    auto finish_field = [&]() {
        if (fields.size() == 2U)
            throw std::runtime_error("CSV record must contain exactly two fields");
        fields.push_back(std::move(field));
        field.clear();
        field_started = false;
        after_quote = false;
    };
    for (;;) {
        const int next = in.get();
        if (next == std::char_traits<char>::eof()) {
            if (in.bad()) throw std::runtime_error("CSV read failure");
            if (quoted) throw std::runtime_error("unterminated quoted field");
            if (!consumed) return false;
            finish_field();
            return true;
        }
        consumed = true;
        add_byte();
        const char c = static_cast<char>(next);
        if (quoted) {
            if (c == '"') {
                if (in.peek() == '"') {
                    (void)in.get();
                    add_byte();
                    append('"');
                } else {
                    quoted = false;
                    after_quote = true;
                }
            } else if (c == '\r') {
                if (in.peek() != '\n')
                    throw std::runtime_error("quoted CR must be followed by LF");
                (void)in.get();
                add_byte();
                append('\r');
                append('\n');
                ++line_number;
            } else {
                append(c);
                if (c == '\n') ++line_number;
            }
            continue;
        }
        if (after_quote) {
            if (c == ',') {
                finish_field();
            } else if (c == '\n') {
                finish_field();
                ++line_number;
                return true;
            } else if (c == '\r') {
                if (in.peek() != '\n')
                    throw std::runtime_error("record CR must be followed by LF");
                (void)in.get();
                add_byte();
                finish_field();
                ++line_number;
                return true;
            } else {
                throw std::runtime_error("characters after closing quote");
            }
            continue;
        }
        if (!field_started && c == '"') {
            quoted = true;
            field_started = true;
        } else if (c == ',') {
            finish_field();
        } else if (c == '\n') {
            finish_field();
            ++line_number;
            return true;
        } else if (c == '\r') {
            if (in.peek() != '\n')
                throw std::runtime_error("record CR must be followed by LF");
            (void)in.get();
            add_byte();
            finish_field();
            ++line_number;
            return true;
        } else if (c == '"') {
            throw std::runtime_error("quote inside unquoted field");
        } else {
            append(c);
            field_started = true;
        }
    }
}

std::int64_t parse_time(const std::string &s) {
    auto digits = [&s](std::size_t first, std::size_t length) {
        if (first + length > s.size()) throw std::runtime_error("invalid observed_at");
        int value = 0;
        for (std::size_t i = first; i < first + length; ++i) {
            const char c = s[i];
            if (c < '0' || c > '9') throw std::runtime_error("invalid observed_at");
            value = value * 10 + (c - '0');
        }
        return value;
    };
    if (s.size() < 20U || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't') ||
        s[13] != ':' || s[16] != ':')
        throw std::runtime_error("observed_at must be RFC 3339");
    const int year = digits(0, 4);
    const int month = digits(5, 2);
    const int day_of_month = digits(8, 2);
    const int hour = digits(11, 2);
    const int minute = digits(14, 2);
    const int second = digits(17, 2);
    if (year == 0 || hour > 23 || minute > 59 || second > 59)
        throw std::runtime_error("observed_at calendar/time value out of range");
    const std::chrono::year_month_day date{std::chrono::year{year},
        std::chrono::month{static_cast<unsigned>(month)},
        std::chrono::day{static_cast<unsigned>(day_of_month)}};
    if (!date.ok()) throw std::runtime_error("observed_at calendar date invalid");
    std::size_t pos = 19;
    if (pos < s.size() && s[pos] == '.') {
        ++pos;
        const std::size_t fraction_start = pos;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
        if (pos == fraction_start) throw std::runtime_error("observed_at fraction must contain digits");
    }
    int offset_seconds = 0;
    if (pos < s.size() && (s[pos] == 'Z' || s[pos] == 'z')) {
        ++pos;
    } else if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) {
        const int sign = s[pos] == '+' ? 1 : -1;
        if (pos + 6U != s.size() || s[pos + 3U] != ':')
            throw std::runtime_error("observed_at offset must be ±HH:MM");
        const int offset_hour = digits(pos + 1U, 2);
        const int offset_minute = digits(pos + 4U, 2);
        if (offset_hour > 23 || offset_minute > 59)
            throw std::runtime_error("observed_at offset out of range");
        offset_seconds = sign * (offset_hour * 3600 + offset_minute * 60);
        pos += 6U;
    } else {
        throw std::runtime_error("observed_at timezone required");
    }
    if (pos != s.size()) throw std::runtime_error("trailing observed_at data");
    const auto day = std::chrono::sys_days{date}.time_since_epoch();
    const auto instant = std::chrono::duration_cast<std::chrono::seconds>(day) +
        std::chrono::hours{hour} + std::chrono::minutes{minute} +
        std::chrono::seconds{second - offset_seconds};
    return instant.count();
}

bool read_limited_line(std::istream &in, std::string &line,
                      std::size_t limit = MAX_RECORD_BYTES) {
    line.clear();
    char c = '\0';
    bool consumed = false;
    while (in.get(c)) {
        consumed = true;
        if (c == '\n') return true;
        if (line.size() == limit)
            throw std::runtime_error("JSON record too large");
        line.push_back(c);
    }
    if (in.bad()) throw std::runtime_error("input read failure");
    return consumed;
}

void enforce_input_file_size(const std::string &path) {
    std::error_code error;
    const std::uintmax_t bytes = std::filesystem::file_size(path, error);
    if (error) throw std::runtime_error("cannot determine input file size: " + path);
    if (bytes > MAX_INPUT_FILE_BYTES)
        throw std::runtime_error("input file exceeds 512 MiB limit: " + path);
}

bool valid_utf8(const std::string &text) {
    const auto *bytes = reinterpret_cast<const unsigned char *>(text.data());
    for (std::size_t i = 0; i < text.size();) {
        const unsigned char lead = bytes[i];
        if (lead <= 0x7fU) { ++i; continue; }
        std::size_t count = 0;
        if (lead >= 0xc2U && lead <= 0xdfU) count = 2;
        else if (lead >= 0xe0U && lead <= 0xefU) count = 3;
        else if (lead >= 0xf0U && lead <= 0xf4U) count = 4;
        else return false;
        if (i + count > text.size()) return false;
        for (std::size_t j = 1; j < count; ++j)
            if ((bytes[i + j] & 0xc0U) != 0x80U) return false;
        if ((lead == 0xe0U && bytes[i + 1U] < 0xa0U) ||
            (lead == 0xedU && bytes[i + 1U] >= 0xa0U) ||
            (lead == 0xf0U && bytes[i + 1U] < 0x90U) ||
            (lead == 0xf4U && bytes[i + 1U] > 0x8fU)) return false;
        i += count;
    }
    return true;
}

std::vector<Event> load_events(const std::string &file) {
    enforce_input_file_size(file);
    std::ifstream in(file, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open input: " + file);
    std::vector<Event> events;
    std::string line;
    std::size_t line_no = 0;
    std::uintmax_t input_bytes = 0;
    for (;;) {
        try {
            if (!read_limited_line(in, line)) break;
        } catch (const std::exception &ex) {
            throw std::runtime_error("line " + std::to_string(line_no + 1U) + ": " + ex.what());
        }
        ++line_no;
        const std::uintmax_t record_bytes = static_cast<std::uintmax_t>(line.size()) + 1U;
        if (record_bytes > MAX_INPUT_FILE_BYTES - input_bytes)
            throw std::runtime_error("input file exceeded 512 MiB limit while reading");
        input_bytes += record_bytes;
        if (line.empty()) continue;
        try {
            if (!valid_utf8(line)) throw std::runtime_error("invalid UTF-8");
            Value root = bdetect::json::Parser(line).parse();
            if (required_text(root, "schema_version") != "event.v1")
                throw std::runtime_error("unsupported schema_version");
            Event e;
            e.id = required_text(root, "event_id");
            e.source = required_text(root, "source");
            e.host = required_text(root, "host_id");
            const Value *producer_session = root.get("producer_session_id");
            const Value *producer_sequence = root.get("producer_sequence");
            if ((producer_session == nullptr) != (producer_sequence == nullptr))
                throw std::runtime_error("producer_session_id and producer_sequence must appear together");
            if (producer_session) {
                const auto *session = std::get_if<std::string>(&producer_session->data);
                const double *sequence = std::get_if<double>(&producer_sequence->data);
                if (!session || session->empty() || session->size() > 128U)
                    throw std::runtime_error("producer_session_id must be a nonempty string of at most 128 bytes");
                if (!sequence || !std::isfinite(*sequence) || std::floor(*sequence) != *sequence ||
                    *sequence < 1.0 || *sequence > 9007199254740991.0)
                    throw std::runtime_error("producer_sequence must be an exact positive safe integer");
                e.producer_session_id = *session;
                e.producer_sequence = static_cast<std::uint64_t>(*sequence);
                e.has_producer_sequence = true;
            }
            e.kind = required_text(root, "kind");
            const std::string severity = required_text(root, "severity");
            e.observed = required_text(root, "observed_at");
            e.epoch = parse_time(e.observed);
            e.content_hash = sha256(line);
            const Value &target = required(root, "target");
            (void)object_value(target, "target");
            e.path = required_text(target, "path");
            validate_optional_integer(target, "device");
            validate_optional_integer(target, "inode");
            const Value &actor = required(root, "actor");
            (void)object_value(actor, "actor");
            validate_nullable_integer(actor, "pid");
            validate_nullable_integer(actor, "start_time_ticks");
            const std::string attribution = required_text(actor, "attribution");
            if (attribution != "unknown" && attribution != "kernel_observed")
                throw std::runtime_error("invalid actor attribution");
            (void)object_value(required(root, "evidence"), "evidence");
            const Value &coverage = required(root, "coverage");
            (void)object_value(coverage, "coverage");
            e.coverage = required_text(coverage, "state");
            if (e.coverage != "healthy" && e.coverage != "degraded" &&
                e.coverage != "unsupported" && e.coverage != "recovering")
                throw std::runtime_error("invalid coverage state");
            if (const Value *reason = coverage.get("reason"); reason &&
                !std::holds_alternative<std::nullptr_t>(reason->data) &&
                !std::holds_alternative<std::string>(reason->data))
                throw std::runtime_error("coverage reason must be string or null");
            const std::set<std::string> severities = {"info", "low", "medium", "high", "critical"};
            if (severity.empty() || !severities.contains(severity))
                throw std::runtime_error("invalid event severity");
            if (e.id.empty() || e.source.empty() || e.host.empty() || e.kind.empty() || e.path.empty())
                throw std::runtime_error("empty required event field");
            if (e.id.size() > 256U || e.source.size() > 128U || e.host.size() > 256U ||
                e.kind.size() > 128U || e.path.size() > 4096U)
                throw std::runtime_error("event field length limit");
            if (events.size() == MAX_EVENT_COUNT)
                throw std::runtime_error("event cardinality limit");
            events.push_back(std::move(e));
        } catch (const std::exception &ex) {
            throw std::runtime_error("line " + std::to_string(line_no) + ": " + ex.what());
        }
    }
    return events;
}

Rules load_rules(const std::string &path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open rules");
    std::string content;
    std::array<char, 4096> buffer{};
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = in.gcount();
        if (count > 0) {
            const auto bytes = static_cast<std::size_t>(count);
            if (bytes > MAX_RECORD_BYTES - content.size())
                throw std::runtime_error("rules file too large");
            content.append(buffer.data(), bytes);
        }
    }
    if (in.bad()) throw std::runtime_error("rules read failure");
    Value v = bdetect::json::Parser(content).parse();
    if (required(v, "schema_version").string_or() != "rules.v1")
        throw std::runtime_error("rules schema must be rules.v1");
    Rules r;
    r.sha256 = sha256(content);
    r.revision = required_text(v, "revision");
    if (r.revision.empty() || r.revision.size() > 128U)
        throw std::runtime_error("rule revision must be nonempty and bounded");
    for (const char *field : {"window_seconds", "lateness_tolerance_ms", "max_entities",
                              "min_event_count", "score_cutoff"})
        (void)required(v, field);
    auto integer = [](const Value &object, const char *key, int fallback, int low, int high) {
        const Value *p = object.get(key);
        if (!p) return fallback;
        const double *number = std::get_if<double>(&p->data);
        if (!number || !std::isfinite(*number) || std::floor(*number) != *number ||
            *number < low || *number > high)
            throw std::runtime_error(std::string("invalid rule integer: ") + key);
        return static_cast<int>(*number);
    };
    r.window = integer(v, "window_seconds", r.window, 10, 60);
    if (r.window != 10 && r.window != 30 && r.window != 60)
        throw std::runtime_error("window_seconds must be 10, 30, or 60");
    r.lateness_ms = integer(v, "lateness_tolerance_ms", r.lateness_ms, 0, 60000);
    r.max_entities = integer(v, "max_entities", r.max_entities, 1, 100000);
    r.min_events = integer(v, "min_event_count", r.min_events, 1, 100000);
    r.cutoff = integer(v, "score_cutoff", r.cutoff, 1, 1000000);
    const Value *rule_values = v.get("rules");
    const auto *rule_array = rule_values ? std::get_if<bdetect::json::Array>(&rule_values->data) : nullptr;
    if (!rule_array || rule_array->empty() || rule_array->size() > 256U)
        throw std::runtime_error("rules must contain 1 to 256 rule objects");
    const std::set<std::string> features = {
        "event_count", "unique_modified_files", "unique_renamed_files",
        "unique_deleted_files", "unique_extension_types"
    };
    const std::set<std::string> operators = {">=", ">", "<=", "<", "=="};
    std::set<std::string> ids;
    for (const Value &entry : *rule_array) {
        Rule rule;
        (void)required(entry, "threshold");
        (void)required(entry, "weight");
        (void)required(entry, "min_sample_count");
        rule.id = required(entry, "id").string_or();
        rule.feature = required(entry, "feature").string_or();
        rule.op = required(entry, "operator").string_or();
        rule.threshold = integer(entry, "threshold", 0, 0, 1000000);
        rule.weight = integer(entry, "weight", -1, 0, 100000);
        rule.min_samples = integer(entry, "min_sample_count", r.min_events, 1, 100000);
        if (rule.id.empty() || rule.id.size() > 128U || !ids.insert(rule.id).second)
            throw std::runtime_error("rule IDs must be nonempty, bounded, and unique");
        if (!features.contains(rule.feature)) throw std::runtime_error("unsupported rule feature: " + rule.feature);
        if (!operators.contains(rule.op)) throw std::runtime_error("unsupported rule operator: " + rule.op);
        r.rules.push_back(std::move(rule));
    }
    return r;
}

using IntakeIssues = std::map<std::string, std::vector<std::string>>;

void add_issue(IntakeIssues &issues, const std::string &host, const std::string &reason) {
    auto &items = issues[host];
    if (std::find(items.begin(), items.end(), reason) == items.end()) items.push_back(reason);
}

bool same_event(const Event &a, const Event &b) {
    return a.content_hash == b.content_hash;
}

std::vector<Event> normalize_events(const std::vector<Event> &input, const Rules &r,
                                    IntakeIssues &issues) {
    std::map<std::string_view, std::int64_t> latest_by_host;
    std::map<std::string_view, std::size_t> by_id;
    std::vector<Event> accepted;
    std::vector<const Event *> unique_events;
    std::set<std::string_view> hosts;
    for (std::size_t event_index = 0; event_index < input.size(); ++event_index) {
        const Event &event = input[event_index];
        hosts.insert(event.host);
        if (hosts.size() > static_cast<std::size_t>(r.max_entities))
            throw std::runtime_error("entity cardinality limit");
        auto duplicate = by_id.find(event.id);
        if (duplicate != by_id.end()) {
            const Event &first = input[duplicate->second];
            if (!same_event(first, event)) {
                add_issue(issues, first.host, "conflicting_duplicate_event_id");
                add_issue(issues, event.host, "conflicting_duplicate_event_id");
                if (first.host != event.host) {
                    accepted.push_back(event);
                    unique_events.push_back(&event);
                }
            }
            continue;
        }
        unique_events.push_back(&event);
        auto latest = latest_by_host.find(event.host);
        if (latest != latest_by_host.end() && event.epoch < latest->second &&
            (latest->second - event.epoch) * 1000 > r.lateness_ms) {
            add_issue(issues, event.host, "late_event_beyond_tolerance");
            by_id.emplace(event.id, event_index);
            continue;
        }
        if (latest == latest_by_host.end() || event.epoch > latest->second)
            latest_by_host[event.host] = event.epoch;
        by_id.emplace(event.id, event_index);
        accepted.push_back(event);
    }
    using SourceKey = std::pair<std::string, std::string>;
    using ProducerKey = std::tuple<std::string, std::string, std::string>;
    std::map<SourceKey, std::pair<bool, bool>> source_sequence_presence;
    std::map<ProducerKey, std::vector<std::pair<std::uint64_t, std::string>>> producer_sequences;
    for (const Event *event : unique_events) {
        auto &presence = source_sequence_presence[{event->host, event->source}];
        if (event->has_producer_sequence) {
            presence.first = true;
            producer_sequences[{event->host, event->source, event->producer_session_id}]
                .emplace_back(event->producer_sequence, event->id);
        } else {
            presence.second = true;
        }
    }
    for (const auto &[source, presence] : source_sequence_presence) {
        if (presence.first && presence.second)
            add_issue(issues, source.first, "producer_sequence_metadata_incomplete");
    }
    for (auto &[producer, sequences] : producer_sequences) {
        std::sort(sequences.begin(), sequences.end(), [](const auto &a, const auto &b) {
            if (a.first != b.first) return a.first < b.first;
            return a.second < b.second;
        });
        for (std::size_t i = 1; i < sequences.size(); ++i) {
            if (sequences[i - 1U].first == sequences[i].first &&
                sequences[i - 1U].second != sequences[i].second) {
                add_issue(issues, std::get<0>(producer), "producer_sequence_conflict");
            } else if (sequences[i - 1U].first < 9007199254740991ULL &&
                       sequences[i].first > sequences[i - 1U].first + 1ULL) {
                add_issue(issues, std::get<0>(producer), "producer_sequence_gap");
            }
        }
    }
    std::stable_sort(accepted.begin(), accepted.end(), [](const Event &a, const Event &b) {
        if (a.host != b.host) return a.host < b.host;
        if (a.epoch != b.epoch) return a.epoch < b.epoch;
        return a.id < b.id;
    });
    return accepted;
}

void pace_replay(const std::vector<Event> &events, double speed) {
    if (!std::isfinite(speed) || speed < 0.0 || speed > 100000.0)
        throw std::runtime_error("replay speed must be between 0 and 100000");
    if (speed == 0.0 || events.empty()) return;
    using Clock = std::chrono::steady_clock;
    std::vector<const Event *> timeline;
    timeline.reserve(events.size());
    for (const Event &event : events) timeline.push_back(&event);
    std::stable_sort(timeline.begin(), timeline.end(), [](const Event *a, const Event *b) {
        if (a->epoch != b->epoch) return a->epoch < b->epoch;
        if (a->host != b->host) return a->host < b->host;
        return a->id < b->id;
    });
    const double total_elapsed = static_cast<double>(timeline.back()->epoch - timeline.front()->epoch) / speed;
    if (!std::isfinite(total_elapsed) || total_elapsed > 3600.0)
        throw std::runtime_error("paced replay duration exceeds one hour");
    const auto origin = Clock::now();
    const std::int64_t first_event_time = timeline.front()->epoch;
    for (const Event *event : timeline) {
        const double elapsed = static_cast<double>(event->epoch - first_event_time) / speed;
        const auto deadline = origin + std::chrono::duration_cast<Clock::duration>(
            std::chrono::duration<double>(elapsed));
        std::this_thread::sleep_until(deadline);
    }
}

std::vector<Decision> evaluate(const std::vector<Event> &events, const Rules &r,
                               const IntakeIssues &issues,
                               std::vector<std::uint64_t> *decision_latency_ns = nullptr) {
    std::map<std::string, std::vector<const Event *>> by_host;
    for (const auto &e : events) by_host[e.host].push_back(&e);
    std::vector<Decision> out;
    for (const auto &[host, host_events] : by_host) {
        std::size_t left = 0;
        std::set<std::int64_t> endpoints;
        for (const Event *event : host_events) endpoints.insert(event->epoch);
        for (std::int64_t end : endpoints) {
            const auto decision_started = decision_latency_ns
                ? std::chrono::steady_clock::now()
                : std::chrono::steady_clock::time_point{};
            const std::int64_t start = end - r.window;
            while (left < host_events.size() && host_events[left]->epoch < start) ++left;
            std::size_t right = left;
            while (right < host_events.size() && host_events[right]->epoch <= end) ++right;
            const std::size_t count = right - left;
            Decision d;
            d.host = host;
            d.start = std::to_string(start);
            d.end = std::to_string(end);
            d.id = "decision-" + std::to_string(out.size() + 1U) + "-" + d.host;
            std::set<std::string> modified, renamed, deleted, extensions, ids;
            std::map<std::string, std::set<std::string>> feature_event_ids;
            bool degraded = false;
            for (std::size_t i = left; i < right; ++i) {
                const Event *e = host_events[i];
                ids.insert(e->id);
                feature_event_ids["event_count"].insert(e->id);
                if (e->coverage != "healthy" && e->coverage != "observed") degraded = true;
                if (e->kind == "file.modified") {
                    modified.insert(e->path);
                    feature_event_ids["unique_modified_files"].insert(e->id);
                }
                if (e->kind == "path.renamed" || e->kind == "file.renamed" || e->kind == "file.moved_to") {
                    renamed.insert(e->path);
                    feature_event_ids["unique_renamed_files"].insert(e->id);
                }
                if (e->kind == "file.deleted") {
                    deleted.insert(e->path);
                    feature_event_ids["unique_deleted_files"].insert(e->id);
                }
                std::size_t slash = e->path.find_last_of('/');
                std::size_t dot = e->path.find_last_of('.');
                if (dot != std::string::npos && (slash == std::string::npos || dot > slash)) {
                    extensions.insert(e->path.substr(dot));
                    feature_event_ids["unique_extension_types"].insert(e->id);
                }
            }
            d.event_ids.assign(ids.begin(), ids.end());
            auto host_issue = issues.find(host);
            if (host_issue != issues.end()) d.unknown = host_issue->second;
            const bool intake_degraded = host_issue != issues.end() && !host_issue->second.empty();
            if (degraded && std::find(d.unknown.begin(), d.unknown.end(), "coverage_degraded") == d.unknown.end())
                d.unknown.push_back("coverage_degraded");
            if (degraded || intake_degraded) {
                d.label = "unknown";
            } else if (count < static_cast<std::size_t>(r.min_events)) {
                d.label = "unknown"; d.unknown.push_back("insufficient_events");
            } else {
                const std::map<std::string, int> feature_values = {
                    {"event_count", static_cast<int>(count)},
                    {"unique_modified_files", static_cast<int>(modified.size())},
                    {"unique_renamed_files", static_cast<int>(renamed.size())},
                    {"unique_deleted_files", static_cast<int>(deleted.size())},
                    {"unique_extension_types", static_cast<int>(extensions.size())}
                };
                for (const Rule &rule : r.rules) {
                    if (count < static_cast<std::size_t>(rule.min_samples)) {
                        d.unknown.push_back("insufficient_sample_count:" + rule.id);
                        continue;
                    }
                    const int observed = feature_values.at(rule.feature);
                    bool matched = false;
                    if (rule.op == ">=") matched = observed >= rule.threshold;
                    else if (rule.op == ">") matched = observed > rule.threshold;
                    else if (rule.op == "<=") matched = observed <= rule.threshold;
                    else if (rule.op == "<") matched = observed < rule.threshold;
                    else if (rule.op == "==") matched = observed == rule.threshold;
                    if (matched) {
                        d.score += rule.weight;
                        Reason reason{rule.id, rule.feature, rule.op, observed,
                                      rule.threshold, rule.weight, rule.weight, {}};
                        const auto evidence = feature_event_ids.find(rule.feature);
                        if (evidence != feature_event_ids.end())
                            reason.source_event_ids.assign(evidence->second.begin(), evidence->second.end());
                        d.reasons.push_back(std::move(reason));
                    }
                }
                d.label = d.unknown.empty() && d.score >= r.cutoff ? "suspicious" :
                          d.unknown.empty() ? "benign" : "unknown";
            }
            if (decision_latency_ns) {
                const auto elapsed = std::chrono::steady_clock::now() - decision_started;
                decision_latency_ns->push_back(static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count()));
            }
            out.push_back(std::move(d));
        }
    }
    return out;
}

void write_decisions(const std::string &path, const std::vector<Decision> &ds,
                     const Rules &r, const std::string &dataset_hash) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot open output");
    for (const auto &d : ds) {
        std::size_t estimate = 1024U;
        auto account_string = [&estimate](const std::string &value) {
            const std::size_t encoded = encoded_string_size(value);
            if (estimate > MAX_DECISION_RECORD_BYTES - 4U ||
                encoded > MAX_DECISION_RECORD_BYTES - estimate - 4U)
                throw std::runtime_error("decision record exceeds output limit");
            estimate += encoded + 4U;
        };
        account_string(d.id);
        account_string(d.host);
        account_string(r.revision);
        account_string(r.sha256);
        account_string(dataset_hash);
        for (const auto &id : d.event_ids) account_string(id);
        for (const auto &unknown : d.unknown) account_string(unknown);
        for (const Reason &reason : d.reasons) {
            if (estimate > MAX_DECISION_RECORD_BYTES - 512U)
                throw std::runtime_error("decision record exceeds output limit");
            estimate += 512U;
            account_string(reason.rule_id);
            account_string(reason.feature);
            account_string(reason.op);
            for (const auto &id : reason.source_event_ids) account_string(id);
        }
        const bool degraded = std::any_of(d.unknown.begin(), d.unknown.end(),
            [](const std::string &reason) { return reason != "insufficient_events"; });
        out << "{\"schema_version\":\"decision.v1\",\"decision_id\":\"" << escape(d.id)
            << "\",\"ruleset_revision\":\"" << escape(r.revision) << "\",\"entity_key\":\""
            << escape(d.host) << "\",\"window_start\":\"" << d.start << "\",\"window_end\":\""
            << d.end << "\",\"score\":" << d.score << ",\"decision\":\"" << d.label
            << "\",\"simulation_only\":true,\"ruleset_sha256\":\"" << r.sha256
            << "\",\"dataset_sha256\":\"" << dataset_hash << "\",\"coverage\":\""
            << (degraded ? "degraded" : "observed") << "\",\"source_event_ids\":[";
        for (std::size_t i = 0; i < d.event_ids.size(); ++i) {
            if (i) out << ',';
            out << '"' << escape(d.event_ids[i]) << '"';
        }
        out << "],\"reasons\":[";
        for (std::size_t i = 0; i < d.reasons.size(); ++i) {
            if (i) out << ',';
            const Reason &reason = d.reasons[i];
            out << "{\"rule_id\":\"" << escape(reason.rule_id)
                << "\",\"feature\":\"" << escape(reason.feature)
                << "\",\"observed\":" << reason.observed
                << ",\"operator\":\"" << escape(reason.op)
                << "\",\"threshold\":" << reason.threshold
                << ",\"weight\":" << reason.weight
                << ",\"contribution\":" << reason.contribution
                << ",\"source_event_ids\":[";
            for (std::size_t j = 0; j < reason.source_event_ids.size(); ++j) {
                if (j) out << ',';
                out << '"' << escape(reason.source_event_ids[j]) << '"';
            }
            out << "]}";
        }
        out << "],\"unknown_fields\":[";
        for (std::size_t i = 0; i < d.unknown.size(); ++i) {
            if (i) out << ',';
            out << '"' << d.unknown[i] << '"';
        }
        out << "]}\n";
    }
}

void write_replay_stats(const std::string &path, std::size_t input_events,
                        std::size_t decisions, std::uint64_t evaluation_duration_ns,
                        std::vector<std::uint64_t> decision_latency_ns) {
    if (decision_latency_ns.size() != decisions)
        throw std::runtime_error("replay latency sample count mismatch");
    std::sort(decision_latency_ns.begin(), decision_latency_ns.end());
    auto percentile = [&decision_latency_ns](unsigned int percent) -> std::string {
        if (decision_latency_ns.empty()) return "null";
        const std::size_t rank =
            (decision_latency_ns.size() * static_cast<std::size_t>(percent) + 99U) / 100U;
        return std::to_string(decision_latency_ns[rank - 1U]);
    };
    const std::string maximum = decision_latency_ns.empty()
        ? "null" : std::to_string(decision_latency_ns.back());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open replay stats output");
    out << "{\"schema_version\":\"bdetect.replay_stats.v1\","
        << "\"measurement_scope\":\"evaluate_only_excludes_input_io_pacing_and_serialization\","
        << "\"input_events\":" << input_events << ",\"decisions\":" << decisions
        << ",\"evaluation_duration_ns\":" << evaluation_duration_ns
        << ",\"decision_latency_ns\":{\"sample_count\":" << decision_latency_ns.size()
        << ",\"p50\":" << percentile(50U)
        << ",\"p95\":" << percentile(95U)
        << ",\"p99\":" << percentile(99U)
        << ",\"max\":" << maximum << "}}\n";
    out.flush();
    if (!out) throw std::runtime_error("cannot write replay stats output");
}

bool same_file_or_path(const std::string &left, const std::string &right) {
    if (left == right) return true;
    std::error_code left_error, right_error;
    const auto left_canonical = std::filesystem::weakly_canonical(left, left_error);
    const auto right_canonical = std::filesystem::weakly_canonical(right, right_error);
    if (!left_error && !right_error && left_canonical == right_canonical) return true;
    struct stat left_stat {}, right_stat {};
    return stat(left.c_str(), &left_stat) == 0 && stat(right.c_str(), &right_stat) == 0 &&
           left_stat.st_dev == right_stat.st_dev && left_stat.st_ino == right_stat.st_ino;
}

void validate_events(const std::string &file) {
    auto events = load_events(file);
    std::cout << "{\"valid\":true,\"records\":" << events.size() << "}\n";
}

struct PredictionRecord {
    std::string entity_key, actual, predicted, window_start, window_end, outcome;
    std::int64_t end_epoch = 0;
    std::string score;
};

void write_csv_cell(std::ostream &out, std::string_view value) {
    out << '"';
    for (char c : value) {
        if (c == '"') out << "\"\"";
        else out << c;
    }
    out << '"';
}

std::string html_escape(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (unsigned char c : value) {
        if (c == '&') escaped += "&amp;";
        else if (c == '<') escaped += "&lt;";
        else if (c == '>') escaped += "&gt;";
        else if (c == '"') escaped += "&quot;";
        else if (c == '\'') escaped += "&#39;";
        else if (c < 0x20U || c == 0x7fU) {
            escaped += "&#";
            escaped += std::to_string(c);
            escaped += ';';
        }
        else escaped.push_back(c);
    }
    return escaped;
}

std::int64_t parse_report_epoch(const std::string &value, const char *field) {
    if (value.empty() || value.size() > 32U)
        throw std::runtime_error(std::string("invalid report window field: ") + field);
    const std::size_t digit_start = value.front() == '-' ? 1U : 0U;
    if (digit_start == value.size())
        throw std::runtime_error(std::string("invalid report window field: ") + field);
    for (std::size_t i = digit_start; i < value.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if (c < '0' || c > '9')
            throw std::runtime_error(std::string("invalid report window field: ") + field);
    }
    std::size_t used = 0;
    long long parsed = 0;
    try { parsed = std::stoll(value, &used, 10); }
    catch (...) { throw std::runtime_error(std::string("invalid report window field: ") + field); }
    if (used != value.size())
        throw std::runtime_error(std::string("invalid report window field: ") + field);
    return static_cast<std::int64_t>(parsed);
}

void evaluate_labels(const std::string &pred_path, const std::string &labels_path,
                     const std::string &report, const std::string &csv_report,
                     const std::string &html_report) {
    enforce_input_file_size(labels_path);
    enforce_input_file_size(pred_path);
    for (const std::string *output : {&report, &csv_report, &html_report}) {
        if (output->empty()) continue;
        if (same_file_or_path(*output, pred_path) || same_file_or_path(*output, labels_path))
            throw std::runtime_error("evaluation report must not replace an input file");
    }
    if (!csv_report.empty() && same_file_or_path(report, csv_report))
        throw std::runtime_error("JSON and CSV reports must use different paths");
    if (!html_report.empty() && (same_file_or_path(report, html_report) ||
                                 (!csv_report.empty() && same_file_or_path(csv_report, html_report))))
        throw std::runtime_error("evaluation reports must use different paths");
    std::map<std::string, std::string> labels;
    std::ifstream l(labels_path);
    if (!l) throw std::runtime_error("cannot open labels");
    std::vector<std::string> fields;
    std::size_t label_line = 1U;
    std::size_t row_start_line = 1U;
    bool first_nonempty_record = true;
    for (;;) {
        try {
            if (!read_csv_record(l, fields, label_line, row_start_line)) break;
        } catch (const std::exception &ex) {
            throw std::runtime_error("bad labels CSV at line " + std::to_string(row_start_line) + ": " + ex.what());
        }
        if (fields.size() == 1U && fields[0].empty()) continue;
        if (first_nonempty_record && fields.size() == 2U &&
            fields[0] == "entity_key" && fields[1] == "label") {
            first_nonempty_record = false;
            continue;
        }
        first_nonempty_record = false;
        if (fields.size() != 2U)
            throw std::runtime_error("bad labels CSV at line " + std::to_string(row_start_line) +
                                     ": expected exactly two fields");
        for (const std::string &value : fields) {
            if (!valid_utf8(value))
                throw std::runtime_error("bad labels CSV at line " + std::to_string(row_start_line) +
                                         ": invalid UTF-8");
            for (unsigned char c : value) {
                if (c < 0x20U && c != '\r' && c != '\n')
                    throw std::runtime_error("bad labels CSV at line " + std::to_string(row_start_line) +
                                             ": control byte in field");
            }
        }
        const std::string &key = fields[0];
        const std::string &label = fields[1];
        if (key.empty() || (label != "benign" && label != "suspicious"))
            throw std::runtime_error("invalid label row at line " + std::to_string(row_start_line));
        if (labels.size() == MAX_LABEL_COUNT)
            throw std::runtime_error("label cardinality limit");
        if (!labels.emplace(key, label).second)
            throw std::runtime_error("duplicate entity label at line " + std::to_string(row_start_line));
    }
    std::ifstream p(pred_path);
    if (!p) throw std::runtime_error("cannot open predictions");
    std::string line;
    int tp=0, fp=0, tn=0, fn=0, unknown=0;
    std::set<std::string> seen_entities;
    std::vector<PredictionRecord> timeline;
    std::size_t prediction_line = 0;
    std::size_t prediction_count = 0;
    std::uintmax_t prediction_bytes = 0;
    while (read_limited_line(p, line, MAX_DECISION_RECORD_BYTES)) {
        ++prediction_line;
        const std::uintmax_t record_bytes = static_cast<std::uintmax_t>(line.size()) + 1U;
        if (record_bytes > MAX_INPUT_FILE_BYTES - prediction_bytes)
            throw std::runtime_error("prediction input exceeded 512 MiB limit");
        prediction_bytes += record_bytes;
        if (line.empty()) continue;
        if (prediction_count == MAX_EVENT_COUNT)
            throw std::runtime_error("prediction cardinality limit");
        ++prediction_count;
        Value v = bdetect::json::Parser(line, MAX_DECISION_RECORD_BYTES).parse();
        std::string key = required_text(v, "entity_key");
        std::string pred = required_text(v, "decision");
        auto it = labels.find(key);
        if (it == labels.end())
            throw std::runtime_error("missing label for prediction line " +
                                     std::to_string(prediction_line) + ": " + key);
        seen_entities.insert(key);
        if (pred != "benign" && pred != "suspicious" && pred != "unknown")
            throw std::runtime_error("invalid prediction label: " + pred);
        bool actual = it->second == "suspicious";
        bool detected = pred == "suspicious";
        std::string outcome;
        if (pred == "unknown") { ++unknown; outcome = "UNKNOWN"; }
        else if (actual && detected) { ++tp; outcome = "TP"; }
        else if (actual) { ++fn; outcome = "FN"; }
        else if (detected) { ++fp; outcome = "FP"; }
        else { ++tn; outcome = "TN"; }
        if (!csv_report.empty() || !html_report.empty()) {
            if (timeline.size() == MAX_LABEL_COUNT)
                throw std::runtime_error("timeline report row limit");
            PredictionRecord row;
            row.entity_key = key;
            row.actual = it->second;
            row.predicted = pred;
            row.outcome = std::move(outcome);
            row.window_start = required_text(v, "window_start");
            row.window_end = required_text(v, "window_end");
            row.end_epoch = parse_report_epoch(row.window_end, "window_end");
            if (row.window_start.size() > 32U) throw std::runtime_error("invalid report window_start");
            if (parse_report_epoch(row.window_start, "window_start") > row.end_epoch)
                throw std::runtime_error("report window_start is after window_end");
            if (const Value *score = v.get("score")) {
                const double *number = std::get_if<double>(&score->data);
                if (!number || !std::isfinite(*number) || std::floor(*number) != *number ||
                    *number < 0 || *number > 1000000.0)
                    throw std::runtime_error("invalid report score");
                row.score = std::to_string(static_cast<int>(*number));
            }
            timeline.push_back(std::move(row));
        }
    }
    for (const auto &[key, label] : labels) {
        (void)label;
        if (!seen_entities.contains(key)) throw std::runtime_error("label has no prediction for " + key);
    }
    auto metric = [](int n, int d) { return d ? std::to_string(static_cast<double>(n) / d) : "N/A"; };
    std::ofstream out(report);
    if (!out) throw std::runtime_error("cannot write report");
    out << "{\"tp\":"<<tp<<",\"fp\":"<<fp<<",\"tn\":"<<tn<<",\"fn\":"<<fn
        <<",\"unknown\":"<<unknown<<",\"total_predictions\":"<<(tp+fp+tn+fn+unknown)
        <<",\"precision\":\""<<metric(tp,tp+fp)<<"\",\"precision_numerator\":"<<tp
        <<",\"precision_denominator\":"<<(tp+fp)<<",\"recall\":\""<<metric(tp,tp+fn)
        <<"\",\"recall_numerator\":"<<tp<<",\"recall_denominator\":"<<(tp+fn)
        <<",\"fpr\":\""<<metric(fp,fp+tn)<<"\",\"fpr_numerator\":"<<fp
        <<",\"fpr_denominator\":"<<(fp+tn)<<",\"fnr\":\""<<metric(fn,fn+tp)
        <<"\",\"fnr_numerator\":"<<fn<<",\"fnr_denominator\":"<<(fn+tp)<<"}\n";
    out.flush();
    if (!out) throw std::runtime_error("cannot finish JSON evaluation report");

    std::sort(timeline.begin(), timeline.end(), [](const PredictionRecord &a, const PredictionRecord &b) {
        if (a.end_epoch != b.end_epoch) return a.end_epoch < b.end_epoch;
        if (a.entity_key != b.entity_key) return a.entity_key < b.entity_key;
        return a.window_start < b.window_start;
    });
    const int total_predictions = tp + fp + tn + fn + unknown;
    const std::array<std::tuple<std::string_view, int, int, std::string>, 10> metrics = {{
        {"tp", tp, tp + fn, std::to_string(tp)}, {"fp", fp, fp + tn, std::to_string(fp)},
        {"tn", tn, tn + fp, std::to_string(tn)}, {"fn", fn, fn + tp, std::to_string(fn)},
        {"unknown", unknown, total_predictions, std::to_string(unknown)},
        {"total_predictions", total_predictions, total_predictions, std::to_string(total_predictions)},
        {"precision", tp, tp + fp, metric(tp, tp + fp)},
        {"recall", tp, tp + fn, metric(tp, tp + fn)},
        {"fpr", fp, fp + tn, metric(fp, fp + tn)},
        {"fnr", fn, fn + tp, metric(fn, fn + tp)}
    }};
    if (!csv_report.empty()) {
        std::ofstream csv(csv_report, std::ios::binary);
        if (!csv) throw std::runtime_error("cannot write CSV evaluation report");
        const std::array<std::string_view, 12> headers = {"record_type", "metric", "entity_key",
            "window_start", "window_end", "actual", "predicted", "outcome", "score",
            "numerator", "denominator", "value"};
        for (std::size_t i = 0; i < headers.size(); ++i) {
            if (i) csv << ',';
            write_csv_cell(csv, headers[i]);
        }
        csv << "\r\n";
        for (const auto &[name, numerator, denominator, value] : metrics) {
            write_csv_cell(csv, "metric"); csv << ','; write_csv_cell(csv, name);
            csv << ",,,,,,," << numerator << ',' << denominator << ',';
            write_csv_cell(csv, value); csv << "\r\n";
        }
        for (const PredictionRecord &row : timeline) {
            write_csv_cell(csv, "decision"); csv << ",,";
            write_csv_cell(csv, row.entity_key); csv << ',';
            write_csv_cell(csv, row.window_start); csv << ',';
            write_csv_cell(csv, row.window_end); csv << ',';
            write_csv_cell(csv, row.actual); csv << ',';
            write_csv_cell(csv, row.predicted); csv << ',';
            write_csv_cell(csv, row.outcome); csv << ',';
            write_csv_cell(csv, row.score); csv << ",,,\r\n";
        }
        csv.flush();
        if (!csv) throw std::runtime_error("cannot finish CSV evaluation report");
    }
    if (!html_report.empty()) {
        std::ofstream html(html_report, std::ios::binary);
        if (!html) throw std::runtime_error("cannot write HTML evaluation report");
        html << "<!doctype html><html lang=\"ko\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>BHD 평가 보고서 / Evaluation report</title>"
                "<style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17212b}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #c8d2dc;padding:.45rem;text-align:left}th{background:#edf2f7}.note{padding:.8rem;background:#fff7df}</style>"
                "<h1>행위 탐지 평가 / Behavior detection evaluation</h1><p class=\"note\">합성 시뮬레이션 평가이며 악성코드 판정이 아닙니다. 파일 경로는 포함하지 않습니다. / Simulation-only fixture evaluation; not a malware verdict. No file paths are included.</p>"
                "<h2>혼동행렬 지표 / Confusion metrics</h2><table><thead><tr><th>지표 / Metric</th><th>분자 / Numerator</th><th>분모 / Denominator</th><th>값 / Value</th></tr></thead><tbody>";
        for (const auto &[name, numerator, denominator, value] : metrics) {
            html << "<tr><td>" << html_escape(name) << "</td><td>" << numerator << "</td><td>"
                 << denominator << "</td><td>" << html_escape(value) << "</td></tr>";
        }
        html << "</tbody></table><h2>판정 시간순 내역 / Decision timeline</h2><table><thead><tr><th>윈도우 종료 / Window end</th><th>윈도우 시작 / Window start</th><th>대상 / Entity</th><th>정답 / Actual</th><th>예측 / Predicted</th><th>결과 / Outcome</th><th>점수 / Score</th></tr></thead><tbody>";
        for (const PredictionRecord &row : timeline) {
            html << "<tr><td>" << html_escape(row.window_end) << "</td><td>"
                 << html_escape(row.window_start) << "</td><td>" << html_escape(row.entity_key)
                 << "</td><td>" << html_escape(row.actual) << "</td><td>"
                 << html_escape(row.predicted) << "</td><td>" << html_escape(row.outcome)
                 << "</td><td>" << html_escape(row.score) << "</td></tr>";
        }
        html << "</tbody></table></html>\n";
        html.flush();
        if (!html) throw std::runtime_error("cannot finish HTML evaluation report");
    }
}

void analyze_rule_correlations(const std::string &input_path, const std::string &report_path) {
    if (same_file_or_path(input_path, report_path))
        throw std::runtime_error("rule analysis report must not replace its input");
    enforce_input_file_size(input_path);
    std::ifstream in(input_path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open decisions for rule analysis");
    std::set<std::string> rules;
    std::map<std::string, std::uint64_t> activations;
    std::map<std::pair<std::string, std::string>, std::uint64_t> coactivations;
    std::string line;
    std::size_t line_number = 0;
    std::uint64_t decision_count = 0;
    std::size_t pair_updates = 0;
    std::uintmax_t input_bytes = 0;
    while (read_limited_line(in, line, MAX_DECISION_RECORD_BYTES)) {
        ++line_number;
        const std::uintmax_t record_bytes = static_cast<std::uintmax_t>(line.size()) + 1U;
        if (record_bytes > MAX_INPUT_FILE_BYTES - input_bytes)
            throw std::runtime_error("rule analysis input exceeded 512 MiB limit");
        input_bytes += record_bytes;
        if (line.empty()) continue;
        if (decision_count == MAX_EVENT_COUNT)
            throw std::runtime_error("rule analysis decision limit");
        Value decision;
        try {
            decision = bdetect::json::Parser(line, MAX_DECISION_RECORD_BYTES).parse();
        } catch (const std::exception &ex) {
            throw std::runtime_error("decision line " + std::to_string(line_number) + ": " + ex.what());
        }
        const Value *reasons_value = decision.get("reasons");
        const auto *reasons = reasons_value
            ? std::get_if<bdetect::json::Array>(&reasons_value->data) : nullptr;
        if (!reasons)
            throw std::runtime_error("decision line " + std::to_string(line_number) +
                                     ": reasons must be an array");
        std::set<std::string> active;
        for (const Value &reason : *reasons) {
            std::string id;
            try { id = required_text(reason, "rule_id"); }
            catch (const std::exception &ex) {
                throw std::runtime_error("decision line " + std::to_string(line_number) +
                                         ": invalid rule reason: " + ex.what());
            }
            if (id.empty() || id.size() > 128U)
                throw std::runtime_error("decision line " + std::to_string(line_number) +
                                         ": rule_id must be nonempty and bounded");
            if (!valid_utf8(id))
                throw std::runtime_error("decision line " + std::to_string(line_number) +
                                         ": rule_id must be valid UTF-8");
            active.insert(std::move(id));
        }
        if (active.size() > 256U)
            throw std::runtime_error("decision line exceeds rule cardinality limit");
        for (const std::string &id : active) {
            rules.insert(id);
            if (rules.size() > 256U) throw std::runtime_error("rule analysis cardinality limit");
            ++activations[id];
        }
        const std::size_t count = active.size();
        const std::size_t updates = count * (count - (count > 0U ? 1U : 0U)) / 2U;
        if (updates > MAX_RULE_PAIR_UPDATES - pair_updates)
            throw std::runtime_error("rule correlation work limit");
        pair_updates += updates;
        for (auto first = active.begin(); first != active.end(); ++first) {
            for (auto second = std::next(first); second != active.end(); ++second)
                ++coactivations[{*first, *second}];
        }
        ++decision_count;
    }
    if (in.bad()) throw std::runtime_error("decision read failure during rule analysis");
    std::ofstream out(report_path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open rule analysis report");
    out << std::setprecision(8)
        << "{\"schema_version\":\"bdetect.rule_analysis.v1\",\"decision_records\":"
        << decision_count << ",\"pair_update_count\":" << pair_updates
        << ",\"rules\":[";
    bool first_rule = true;
    for (const std::string &id : rules) {
        if (!first_rule) out << ',';
        first_rule = false;
        out << "{\"rule_id\":\"" << escape(id) << "\",\"active_decisions\":"
            << activations[id] << '}';
    }
    out << "],\"pairs\":[";
    bool first_pair = true;
    for (auto first = rules.begin(); first != rules.end(); ++first) {
        for (auto second = std::next(first); second != rules.end(); ++second) {
            const std::uint64_t both = coactivations[{*first, *second}];
            const std::uint64_t first_active = activations[*first];
            const std::uint64_t second_active = activations[*second];
            const std::uint64_t first_only = first_active - both;
            const std::uint64_t second_only = second_active - both;
            const std::uint64_t neither = decision_count - both - first_only - second_only;
            const std::uint64_t union_count = both + first_only + second_only;
            const long double phi_denominator = std::sqrt(
                static_cast<long double>(first_active) * second_active *
                (decision_count - first_active) * (decision_count - second_active));
            if (!first_pair) out << ',';
            first_pair = false;
            out << "{\"rule_a\":\"" << escape(*first) << "\",\"rule_b\":\""
                << escape(*second) << "\",\"both\":" << both
                << ",\"a_only\":" << first_only << ",\"b_only\":" << second_only
                << ",\"neither\":" << neither << ",\"jaccard\":";
            if (union_count == 0U) out << "null";
            else out << static_cast<double>(both) / static_cast<double>(union_count);
            out << ",\"phi\":";
            if (phi_denominator == 0.0L) out << "null";
            else {
                const long double numerator = static_cast<long double>(both) * neither -
                    static_cast<long double>(first_only) * second_only;
                out << static_cast<double>(numerator / phi_denominator);
            }
            out << '}';
        }
    }
    out << "],\"interpretation\":\"descriptive co-activation only; overlapping windows are dependent; no rule weights are changed\"}\n";
    out.flush();
    if (!out) throw std::runtime_error("cannot finish rule analysis report");
}

void generate_fixtures(const std::string &outdir, const std::string &root) {
    char root_real[4096], out_real[4096];
    struct stat root_stat {};
    if (!realpath(root.c_str(), root_real) || lstat(root_real, &root_stat) != 0 ||
        !S_ISDIR(root_stat.st_mode))
        throw std::runtime_error("fixture root must already exist");
    if (mkdir(outdir.c_str(), 0700) != 0) throw std::runtime_error("output directory must not exist");
    if (!realpath(outdir.c_str(), out_real)) throw std::runtime_error("cannot resolve output directory");
    std::string prefix = std::string(root_real) + "/";
    if (std::string(out_real).rfind(prefix, 0) != 0) {
        rmdir(out_real); throw std::runtime_error("output must be inside sandbox root");
    }
    std::vector<std::pair<std::string,std::string>> scenarios = {
        {"compiler-build","normal"},{"git-checkout","normal"},{"package-install","normal"},
        {"backup","normal"},{"archive","normal"},{"ide-save","normal"},{"sync","normal"},
        {"log-rotation","normal"},{"rapid-rewrite","synthetic_suspicious"},
        {"mass-rename","synthetic_suspicious"},{"mass-delete","synthetic_suspicious"},
        {"mixed-burst","synthetic_suspicious"}
    };
    std::ofstream labels(std::string(out_real) + "/labels.csv");
    labels << "entity_key,label\n";
    for (const auto &[name, category] : scenarios) {
        std::string host = name;
        std::ofstream file(std::string(out_real) + "/" + name + ".ndjson");
        int count = category == "normal" ? 12 : 50;
        for (int i = 0; i < count; ++i) {
            std::string kind = "file.modified";
            if (name == "backup") kind = "file.read";
            else if (name == "compiler-build") kind = i < 8 ? "file.created" : "file.modified";
            else if (name == "git-checkout")
                kind = i < 5 ? "file.created" : i < 10 ? "file.modified" : "file.deleted";
            else if (name == "package-install") kind = i < 10 ? "file.created" : "file.modified";
            else if (name == "archive") kind = i < 8 ? "file.created" : "file.modified";
            else if (name == "ide-save") kind = "file.modified";
            else if (name == "sync") kind = i < 5 ? "file.created" : i < 10 ? "file.modified" : "file.renamed";
            else if (name == "log-rotation")
                kind = i == 0 ? "file.renamed" : i == 1 ? "file.deleted" : "file.created";
            else if (name == "mass-rename") kind = "file.renamed";
            else if (name == "mass-delete") kind = "file.deleted";
            else if (name == "mixed-burst")
                kind = i < 40 ? "file.modified" : i < 45 ? "file.renamed" : "file.deleted";
            const char *ts = "2026-10-09T12:00:00Z";
            const std::string item = name == "ide-save" ? "document" : "item" + std::to_string(i);
            std::string path = "/sandbox/" + name + "/" + item +
                               (name == "ide-save" ? ".txt" : i % 2 ? ".dat" : ".txt");
            file << "{\"schema_version\":\"event.v1\",\"event_id\":\"" << name << "-"
                 << i << "\",\"source\":\"fixture\",\"host_id\":\"" << host
                 << "\",\"observed_at\":\"" << ts << "\",\"kind\":\"" << kind
                 << "\",\"severity\":\"info\",\"target\":{\"path\":\"" << path
                 << "\"},\"actor\":{\"pid\":null,\"start_time_ticks\":null,\"attribution\":\"unknown\"},"
                    "\"evidence\":{},\"coverage\":{\"state\":\"healthy\"}}\n";
        }
        labels << host << ',' << (category == "normal" ? "benign" : "suspicious") << '\n';
    }
    std::cout << "synthetic fixtures created under " << out_real << '\n';
}
} // namespace

static std::string arg(int argc, char **argv, const std::string &name, const std::string &fallback={}) {
    for (int i = 2; i + 1 < argc; ++i) if (argv[i] == name) return argv[i+1];
    return fallback;
}

int main(int argc, char **argv) {
    try {
        if (argc < 2 || std::string(argv[1]) == "--help") {
            std::cout << "bdetect replay --input FILE --rules FILE --out FILE [--speed EVENT_TIME_MULTIPLIER] [--stats-out FILE]\n"
                         "bdetect evaluate --pred FILE --labels CSV --report FILE [--csv-report FILE] [--html-report FILE]\n"
                         "bdetect analyze-rules --input DECISIONS --report FILE\n"
                         "bdetect rules-validate --file FILE\n"
                         "bdetect generate-fixtures --root SANDBOX --out NEW-DIR\n"
                         "bdetect explain --decision-id ID --input DECISIONS\n";
            return argc < 2 ? 2 : 0;
        }
        std::string command = argv[1];
        if (command == "rules-validate") {
            (void)load_rules(arg(argc, argv, "--file"));
            puts("{\"valid\":true}");
        } else if (command == "generate-fixtures") {
            generate_fixtures(arg(argc, argv, "--out"), arg(argc, argv, "--root"));
        } else if (command == "replay") {
            Rules rules = load_rules(arg(argc, argv, "--rules"));
            const std::string input_path = arg(argc, argv, "--input");
            enforce_input_file_size(input_path);
            const std::string dataset_hash = sha256_file(input_path);
            auto input_events = load_events(input_path);
            if (sha256_file(input_path) != dataset_hash)
                throw std::runtime_error("input changed while replay was loading");
            IntakeIssues issues;
            auto events = normalize_events(input_events, rules, issues);
            std::size_t speed_bytes = 0;
            const std::string speed_arg = arg(argc, argv, "--speed", "0");
            double speed = 0.0;
            try { speed = std::stod(speed_arg, &speed_bytes); }
            catch (...) { throw std::runtime_error("invalid replay speed"); }
            if (speed_bytes != speed_arg.size()) throw std::runtime_error("invalid replay speed");
            pace_replay(events, speed);
            const std::string output_path = arg(argc, argv, "--out");
            const std::string stats_path = arg(argc, argv, "--stats-out");
            bool stats_requested = false;
            for (int i = 2; i < argc; ++i)
                if (std::string(argv[i]) == "--stats-out") stats_requested = true;
            if (stats_requested && stats_path.empty())
                throw std::runtime_error("--stats-out requires a file path");
            if (!stats_path.empty() &&
                (same_file_or_path(stats_path, input_path) ||
                 same_file_or_path(stats_path, arg(argc, argv, "--rules")) ||
                 same_file_or_path(stats_path, output_path)))
                throw std::runtime_error("replay stats output must be a separate file");
            std::vector<std::uint64_t> decision_latency_ns;
            const auto evaluation_started = std::chrono::steady_clock::now();
            auto decisions = evaluate(events, rules, issues,
                                      stats_path.empty() ? nullptr : &decision_latency_ns);
            const auto evaluation_elapsed = std::chrono::steady_clock::now() - evaluation_started;
            const auto evaluation_duration_ns = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(evaluation_elapsed).count());
            write_decisions(output_path, decisions, rules, dataset_hash);
            if (!stats_path.empty())
                write_replay_stats(stats_path, input_events.size(), decisions.size(),
                                   evaluation_duration_ns, std::move(decision_latency_ns));
            std::cout << "decisions=" << decisions.size() << " simulation_only=true\n";
        } else if (command == "evaluate") {
            evaluate_labels(arg(argc, argv, "--pred"), arg(argc, argv, "--labels"),
                            arg(argc, argv, "--report"), arg(argc, argv, "--csv-report"),
                            arg(argc, argv, "--html-report"));
        } else if (command == "analyze-rules") {
            analyze_rule_correlations(arg(argc, argv, "--input"), arg(argc, argv, "--report"));
        } else if (command == "explain") {
            std::string wanted = arg(argc, argv, "--decision-id");
            const std::string decision_path = arg(argc, argv, "--input");
            enforce_input_file_size(decision_path);
            std::ifstream in(decision_path, std::ios::binary);
            if (!in) throw std::runtime_error("cannot open decisions");
            std::string line; bool found=false;
            std::uintmax_t input_bytes = 0;
            while (read_limited_line(in, line, MAX_DECISION_RECORD_BYTES)) {
                const std::uintmax_t record_bytes = static_cast<std::uintmax_t>(line.size()) + 1U;
                if (record_bytes > MAX_INPUT_FILE_BYTES - input_bytes)
                    throw std::runtime_error("decision input exceeded 512 MiB limit");
                input_bytes += record_bytes;
                Value v=bdetect::json::Parser(line, MAX_DECISION_RECORD_BYTES).parse();
                if (required(v,"decision_id").string_or()==wanted) { std::cout<<line<<'\n'; found=true; break; }
            }
            if (!found) throw std::runtime_error("decision ID not found");
        } else if (command == "validate-events") {
            validate_events(arg(argc, argv, "--input"));
        } else {
            throw std::runtime_error("unknown command");
        }
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "bdetect: " << e.what() << '\n';
        return 2;
    }
}
