#include "bdetect/json.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <fcntl.h>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
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
#include <sys/file.h>
#include <unistd.h>

namespace {
using bdetect::json::Value;
constexpr std::size_t MAX_RECORD_BYTES = 1024U * 1024U;
constexpr std::size_t MAX_DECISION_RECORD_BYTES = 64U * 1024U * 1024U;
constexpr std::size_t MAX_DECISION_REASON_EVIDENCE_BYTES = 32U * 1024U * 1024U;
constexpr std::uintmax_t MAX_INPUT_FILE_BYTES = 512U * 1024U * 1024U;
constexpr std::size_t MAX_EVENT_COUNT = 1000000U;
constexpr std::size_t MAX_LABEL_COUNT = 100000U;
constexpr std::size_t MAX_LABEL_FIELD_BYTES = 256U;
constexpr std::size_t MAX_RULE_PAIR_UPDATES = 10000000U;
constexpr std::size_t MAX_STREAM_QUEUE_COUNT = 4096U;
constexpr std::size_t MAX_STREAM_QUEUE_BYTES = 64U * 1024U * 1024U;
constexpr std::size_t MAX_STREAM_OVERFLOW_MARKERS = 4096U;
constexpr std::size_t MAX_STREAM_ACTIVE_EVENTS = 100000U;
constexpr std::size_t MAX_STREAM_ACTIVE_BYTES = 64U * 1024U * 1024U;
constexpr std::size_t MAX_STREAM_ID_CACHE = 100000U;
struct Event {
    std::string id, source, host, kind, path, observed, coverage, content_hash;
    std::string producer_session_id;
    std::uint64_t producer_sequence = 0;
    bool has_producer_sequence = false;
    std::int64_t epoch = 0;
    std::size_t record_bytes = 0;
};

void release_event_payload(Event &event) {
    std::string{}.swap(event.id);
    std::string{}.swap(event.source);
    std::string{}.swap(event.host);
    std::string{}.swap(event.kind);
    std::string{}.swap(event.path);
    std::string{}.swap(event.observed);
    std::string{}.swap(event.coverage);
    std::string{}.swap(event.content_hash);
    std::string{}.swap(event.producer_session_id);
}
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

std::uintmax_t bounded_input_file_size(const std::string &path) {
    std::error_code error;
    const std::uintmax_t bytes = std::filesystem::file_size(path, error);
    if (error) throw std::runtime_error("cannot determine input file size: " + path);
    if (bytes > MAX_INPUT_FILE_BYTES)
        throw std::runtime_error("input file exceeds 512 MiB limit: " + path);
    return bytes;
}

void enforce_input_file_size(const std::string &path) {
    (void)bounded_input_file_size(path);
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

Event parse_event_line(const std::string &line) {
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
    e.record_bytes = line.size();
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
    return e;
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
            if (events.size() == MAX_EVENT_COUNT) throw std::runtime_error("event cardinality limit");
            events.push_back(parse_event_line(line));
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

std::vector<Decision> evaluate(std::vector<Event> &events, const Rules &r,
                               const IntakeIssues &issues,
                               std::vector<std::uint64_t> *decision_latency_ns = nullptr,
                               std::optional<std::int64_t> only_end = std::nullopt) {
    std::map<std::string, std::vector<Event *>> by_host;
    for (Event &e : events) by_host[e.host].push_back(&e);
    std::vector<Decision> out;
    for (const auto &[host, host_events] : by_host) {
        std::size_t left = 0;
        std::size_t right_cursor = 0;
        for (std::size_t endpoint = 0; endpoint < host_events.size();) {
            const std::int64_t end = host_events[endpoint]->epoch;
            while (endpoint < host_events.size() && host_events[endpoint]->epoch == end) ++endpoint;
            const auto decision_started = decision_latency_ns
                ? std::chrono::steady_clock::now()
                : std::chrono::steady_clock::time_point{};
            const std::int64_t start = end - r.window;
            while (left < host_events.size() && host_events[left]->epoch < start) {
                release_event_payload(*host_events[left]);
                ++left;
            }
            if (right_cursor < left) right_cursor = left;
            while (right_cursor < host_events.size() && host_events[right_cursor]->epoch <= end)
                ++right_cursor;
            const std::size_t right = right_cursor;
            if (only_end && end != *only_end) continue;
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
            std::size_t reason_evidence_bytes = 0;
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
                        if (evidence != feature_event_ids.end()) {
                            for (const std::string &event_id : evidence->second) {
                                const std::size_t encoded_bytes = encoded_string_size(event_id);
                                if (encoded_bytes > MAX_DECISION_REASON_EVIDENCE_BYTES - reason_evidence_bytes)
                                    throw std::runtime_error("decision rule evidence exceeds 32 MiB limit");
                                reason_evidence_bytes += encoded_bytes;
                            }
                            reason.source_event_ids.assign(evidence->second.begin(), evidence->second.end());
                        }
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
        for (std::size_t i = left; i < host_events.size(); ++i)
            release_event_payload(*host_events[i]);
    }
    return out;
}

std::string serialize_decision(const Decision &d, const Rules &r,
                               const std::string &dataset_hash) {
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
        std::ostringstream out;
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
            out << '"' << escape(d.unknown[i]) << '"';
        }
        out << "]}";
        std::string record = out.str();
        if (record.size() > MAX_DECISION_RECORD_BYTES)
            throw std::runtime_error("decision record exceeds output limit");
        return record;
}

void write_decisions(const std::string &path, const std::vector<Decision> &ds,
                     const Rules &r, const std::string &dataset_hash) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot open output");
    for (const auto &d : ds) {
        out << serialize_decision(d, r, dataset_hash) << '\n';
        if (!out) throw std::runtime_error("cannot write output");
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

void write_all_fd(int fd, std::string_view content) {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const ssize_t written = write(fd, content.data() + offset, content.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) throw std::runtime_error("file write failed");
        offset += static_cast<std::size_t>(written);
    }
}

class AtomicDecisionOutput {
public:
    explicit AtomicDecisionOutput(std::string target)
        : target_(std::move(target)), temporary_(target_ + ".tmp." + std::to_string(getpid()) + ".stream") {
        if (target_.empty()) throw std::runtime_error("--out requires a file path");
        fd_ = open(temporary_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0) throw std::runtime_error("cannot create temporary replay output");
    }

    ~AtomicDecisionOutput() {
        if (fd_ >= 0) (void)close(fd_);
        if (!committed_) (void)unlink(temporary_.c_str());
    }

    AtomicDecisionOutput(const AtomicDecisionOutput &) = delete;
    AtomicDecisionOutput &operator=(const AtomicDecisionOutput &) = delete;

    void append(std::string_view record) {
        if (record.size() >= MAX_INPUT_FILE_BYTES ||
            output_bytes_ > MAX_INPUT_FILE_BYTES - record.size() - 1U)
            throw std::runtime_error("stream decision output exceeds 512 MiB limit");
        write_all_fd(fd_, record);
        write_all_fd(fd_, "\n");
        output_bytes_ += record.size() + 1U;
    }

    void commit() {
        if (fsync(fd_) != 0) throw std::runtime_error("cannot persist replay output");
        const int close_status = close(fd_);
        fd_ = -1;
        if (close_status != 0) throw std::runtime_error("cannot close replay output");
        if (rename(temporary_.c_str(), target_.c_str()) != 0)
            throw std::runtime_error("cannot publish replay output");
        committed_ = true;
    }

private:
    std::string target_;
    std::string temporary_;
    std::uintmax_t output_bytes_ = 0;
    int fd_ = -1;
    bool committed_ = false;
};

int next_input_byte(int fd, std::array<char, 65536> &buffer,
                    std::size_t &position, std::size_t &available) {
    if (position == available) {
        for (;;) {
            const ssize_t count = read(fd, buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw std::runtime_error("stream input read failure");
            if (count == 0) return -1;
            position = 0;
            available = static_cast<std::size_t>(count);
            break;
        }
    }
    return static_cast<unsigned char>(buffer[position++]);
}

bool read_stream_line(int fd, std::array<char, 65536> &buffer,
                      std::size_t &position, std::size_t &available,
                      std::string &line, bool &had_newline) {
    line.clear();
    had_newline = false;
    bool consumed = false;
    for (;;) {
        const int byte = next_input_byte(fd, buffer, position, available);
        if (byte < 0) return consumed;
        consumed = true;
        if (byte == '\n') {
            had_newline = true;
            return true;
        }
        if (line.size() == MAX_RECORD_BYTES)
            throw std::runtime_error("JSON record too large");
        line.push_back(static_cast<char>(byte));
    }
}

std::string sha256_fd(int fd, std::uintmax_t expected_size) {
    using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    DigestContext digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("stream input SHA-256 initialization failed");
    std::array<char, 65536> buffer{};
    std::uintmax_t offset = 0;
    while (offset < expected_size) {
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uintmax_t>(buffer.size(), expected_size - offset));
        ssize_t count = -1;
        do {
            count = pread(fd, buffer.data(), requested, static_cast<off_t>(offset));
        } while (count < 0 && errno == EINTR);
        if (count <= 0) throw std::runtime_error("stream input changed while hashing");
        if (EVP_DigestUpdate(digest.get(), buffer.data(), static_cast<std::size_t>(count)) != 1)
            throw std::runtime_error("stream input SHA-256 update failed");
        offset += static_cast<std::uintmax_t>(count);
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
    unsigned int size = 0;
    if (EVP_DigestFinal_ex(digest.get(), bytes.data(), &size) != 1)
        throw std::runtime_error("stream input SHA-256 finalization failed");
    std::ostringstream text;
    text << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < size; ++i)
        text << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    return text.str();
}

struct StreamSeenId {
    std::string content_hash;
    std::int64_t epoch = 0;
};

std::size_t stream_replay(const std::string &input_path, const std::string &rules_path,
                          const std::string &output_path, const Rules &rules, double speed) {
    if (input_path.empty() || output_path.empty())
        throw std::runtime_error("stream replay requires --input and --out");
    if (same_file_or_path(input_path, output_path) || same_file_or_path(rules_path, output_path))
        throw std::runtime_error("replay output must be separate from input and rules");
    if (!std::isfinite(speed) || speed < 0.0 || speed > 100000.0)
        throw std::runtime_error("replay speed must be between 0 and 100000");

    const int input_fd = open(input_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (input_fd < 0) throw std::runtime_error("cannot securely open stream input");
    struct InputGuard {
        int fd;
        ~InputGuard() { if (fd >= 0) (void)close(fd); }
    } input_guard{input_fd};
    struct stat initial_stat {};
    if (fstat(input_fd, &initial_stat) != 0 || !S_ISREG(initial_stat.st_mode) ||
        initial_stat.st_size < 0 || static_cast<std::uintmax_t>(initial_stat.st_size) > MAX_INPUT_FILE_BYTES)
        throw std::runtime_error("stream input must be a regular file of at most 512 MiB");
    const std::string dataset_hash = sha256_fd(input_fd, static_cast<std::uintmax_t>(initial_stat.st_size));
    using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    DigestContext consumed_digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!consumed_digest || EVP_DigestInit_ex(consumed_digest.get(), EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("stream input SHA-256 initialization failed");

    AtomicDecisionOutput output(output_path);
    std::array<char, 65536> input_buffer{};
    std::size_t buffer_position = 0, buffer_available = 0;
    std::string line;
    std::uintmax_t input_bytes = 0;
    std::size_t line_number = 0, event_count = 0, decision_count = 0;
    bool have_max_event_epoch = false;
    std::int64_t max_event_epoch = 0;
    bool have_flushed_epoch = false;
    std::int64_t last_flushed_epoch = 0;
    std::map<std::int64_t, std::map<std::string, std::vector<Event>>> pending_epochs;
    std::set<std::string> seen_hosts;
    std::size_t queued_count = 0, queued_bytes = 0, overflow_marker_count = 0;
    std::map<std::string, std::deque<Event>> active;
    std::deque<std::pair<std::string, std::int64_t>> active_order;
    std::size_t active_count = 0, active_bytes = 0;
    std::map<std::string, StreamSeenId> seen_ids;
    std::multimap<std::int64_t, std::string> seen_id_order;
    std::map<std::string, std::map<std::string, std::int64_t>> issue_until;
    bool have_first_epoch = false;
    std::int64_t first_epoch = 0;
    const std::int64_t allowed_lateness_seconds =
        static_cast<std::int64_t>(rules.lateness_ms) / 1000;
    const auto pacing_origin = std::chrono::steady_clock::now();

    auto mark_issue = [&issue_until, &rules](const std::string &host, const std::string &reason,
                                            std::int64_t epoch) {
        const std::int64_t expiry = epoch + rules.window;
        auto &host_reasons = issue_until[host];
        const auto found = host_reasons.find(reason);
        if (found == host_reasons.end()) host_reasons.emplace(reason, expiry);
        else found->second = std::max(found->second, expiry);
    };
    auto flush_endpoint = [&](std::int64_t epoch) {
        if (speed > 0.0) {
            if (!have_first_epoch) {
                have_first_epoch = true;
                first_epoch = epoch;
            }
            const double elapsed = static_cast<double>(epoch - first_epoch) / speed;
            if (!std::isfinite(elapsed) || elapsed > 3600.0)
                throw std::runtime_error("paced stream replay duration exceeds one hour");
            const auto deadline = pacing_origin + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                std::chrono::duration<double>(elapsed));
            std::this_thread::sleep_until(deadline);
        }

        const std::int64_t window_start = epoch - rules.window;
        while (!active_order.empty() && active_order.front().second < window_start) {
            const auto [host, event_epoch] = std::move(active_order.front());
            active_order.pop_front();
            auto host_active = active.find(host);
            if (host_active == active.end() || host_active->second.empty() ||
                host_active->second.front().epoch != event_epoch)
                throw std::runtime_error("stream active-window index is inconsistent");
            active_bytes -= host_active->second.front().record_bytes;
            release_event_payload(host_active->second.front());
            host_active->second.pop_front();
            --active_count;
            if (host_active->second.empty()) active.erase(host_active);
        }

        std::set<std::string> endpoint_hosts;
        const auto endpoint = pending_epochs.find(epoch);
        if (endpoint != pending_epochs.end()) {
            for (auto &[host, events] : endpoint->second) {
                endpoint_hosts.insert(host);
                if (events.empty()) --overflow_marker_count;
                std::sort(events.begin(), events.end(), [](const Event &left, const Event &right) {
                    return left.id < right.id;
                });
                for (Event &event : events) {
                    queued_bytes -= event.record_bytes;
                    --queued_count;
                    if (active_count >= MAX_STREAM_ACTIVE_EVENTS ||
                        event.record_bytes > MAX_STREAM_ACTIVE_BYTES - active_bytes) {
                        mark_issue(host, "active_window_capacity_exceeded", epoch);
                        continue;
                    }
                    const std::int64_t event_epoch = event.epoch;
                    active_bytes += event.record_bytes;
                    ++active_count;
                    active[host].push_back(std::move(event));
                    active_order.emplace_back(host, event_epoch);
                }
            }
            pending_epochs.erase(endpoint);
        }

        for (const std::string &host : endpoint_hosts) {
            IntakeIssues endpoint_issues;
            const auto host_issues = issue_until.find(host);
            if (host_issues != issue_until.end()) {
                for (const auto &[reason, expiry] : host_issues->second)
                    if (epoch <= expiry) add_issue(endpoint_issues, host, reason);
            }

            std::vector<Event> snapshot;
            const auto host_active = active.find(host);
            if (host_active != active.end())
                snapshot.assign(host_active->second.begin(), host_active->second.end());
            auto decisions = evaluate(snapshot, rules, endpoint_issues, nullptr, epoch);
            Decision decision;
            if (decisions.empty()) {
                decision.host = host;
                decision.start = std::to_string(window_start);
                decision.end = std::to_string(epoch);
                decision.label = "unknown";
                decision.unknown = endpoint_issues[host];
                if (decision.unknown.empty())
                    decision.unknown.push_back("bounded_reorder_queue_overflow");
                std::set<std::string> event_ids;
                if (host_active != active.end())
                    for (const Event &event : host_active->second)
                        if (event.epoch >= window_start && event.epoch <= epoch)
                            event_ids.insert(event.id);
                decision.event_ids.assign(event_ids.begin(), event_ids.end());
            } else {
                decision = std::move(decisions.front());
            }
            decision.id = "decision-" + std::to_string(++decision_count) + "-" + host;
            output.append(serialize_decision(decision, rules, dataset_hash));
        }
        last_flushed_epoch = epoch;
        have_flushed_epoch = true;

    };

    auto flush_ready = [&](std::int64_t watermark) {
        while (!pending_epochs.empty() && pending_epochs.begin()->first < watermark)
            flush_endpoint(pending_epochs.begin()->first);
    };

    bool had_newline = false;
    for (;;) {
        try {
            if (!read_stream_line(input_fd, input_buffer, buffer_position, buffer_available,
                                  line, had_newline))
                break;
        } catch (const std::exception &ex) {
            throw std::runtime_error("line " + std::to_string(line_number + 1U) + ": " + ex.what());
        }
        ++line_number;
        const std::uintmax_t row_bytes = static_cast<std::uintmax_t>(line.size()) +
                                         (had_newline ? 1U : 0U);
        if (row_bytes > MAX_INPUT_FILE_BYTES - input_bytes)
            throw std::runtime_error("stream input exceeded 512 MiB limit while reading");
        input_bytes += row_bytes;
        if ((!line.empty() && EVP_DigestUpdate(consumed_digest.get(), line.data(), line.size()) != 1) ||
            (had_newline && EVP_DigestUpdate(consumed_digest.get(), "\n", 1U) != 1))
            throw std::runtime_error("stream input SHA-256 update failed");
        if (line.empty()) continue;
        if (event_count == MAX_EVENT_COUNT)
            throw std::runtime_error("stream event cardinality limit");
        ++event_count;

        Event event;
        try {
            event = parse_event_line(line);
        } catch (const std::exception &ex) {
            throw std::runtime_error("line " + std::to_string(line_number) + ": " + ex.what());
        }
        if (event.has_producer_sequence)
            throw std::runtime_error("--stream does not accept producer sequence metadata; use batch replay");
        if (have_flushed_epoch && event.epoch <= last_flushed_epoch)
            throw std::runtime_error("event arrived behind the stream watermark; use batch replay");
        if (have_max_event_epoch && event.epoch < max_event_epoch - allowed_lateness_seconds)
            throw std::runtime_error("event exceeds the configured stream lateness tolerance; use batch replay");
        if (!have_max_event_epoch || event.epoch > max_event_epoch) {
            max_event_epoch = event.epoch;
            have_max_event_epoch = true;
        }
        const std::int64_t watermark = max_event_epoch - allowed_lateness_seconds;

        const std::int64_t retention = static_cast<std::int64_t>(rules.window) + allowed_lateness_seconds;
        const std::int64_t id_cutoff = max_event_epoch - retention;
        while (!seen_id_order.empty() && seen_id_order.begin()->first < id_cutoff) {
            const std::int64_t old_epoch = seen_id_order.begin()->first;
            const std::string old_id = std::move(seen_id_order.begin()->second);
            const auto found = seen_ids.find(old_id);
            if (found != seen_ids.end() && found->second.epoch == old_epoch)
                seen_ids.erase(found);
            seen_id_order.erase(seen_id_order.begin());
        }
        auto duplicate = seen_ids.find(event.id);
        if (duplicate != seen_ids.end()) {
            if (duplicate->second.content_hash != event.content_hash)
                throw std::runtime_error("conflicting duplicate event_id in stream");
            flush_ready(watermark);
            continue;
        }
        if (seen_hosts.insert(event.host).second && seen_hosts.size() > static_cast<std::size_t>(rules.max_entities))
            throw std::runtime_error("stream entity cardinality limit");
        if (seen_ids.size() >= MAX_STREAM_ID_CACHE)
            throw std::runtime_error("stream event ID cache limit reached; use batch replay");
        seen_ids.emplace(event.id, StreamSeenId{event.content_hash, event.epoch});
        seen_id_order.emplace(event.epoch, event.id);

        const bool queue_overflow = queued_count >= MAX_STREAM_QUEUE_COUNT ||
            event.record_bytes > MAX_STREAM_QUEUE_BYTES - queued_bytes;
        auto &epoch_hosts = pending_epochs[event.epoch];
        auto host_position = epoch_hosts.find(event.host);
        if (queue_overflow) {
            if (host_position == epoch_hosts.end()) {
                if (overflow_marker_count >= MAX_STREAM_OVERFLOW_MARKERS)
                    throw std::runtime_error("stream overflow marker limit reached");
                epoch_hosts.try_emplace(event.host);
                ++overflow_marker_count;
            }
            mark_issue(event.host, "bounded_reorder_queue_overflow", event.epoch);
        } else {
            if (host_position == epoch_hosts.end())
                host_position = epoch_hosts.try_emplace(event.host).first;
            else if (host_position->second.empty())
                --overflow_marker_count;
            queued_bytes += event.record_bytes;
            ++queued_count;
            host_position->second.push_back(std::move(event));
        }
        flush_ready(watermark);
    }
    while (!pending_epochs.empty()) flush_endpoint(pending_epochs.begin()->first);

    std::array<unsigned char, EVP_MAX_MD_SIZE> consumed_bytes{};
    unsigned int consumed_size = 0;
    if (EVP_DigestFinal_ex(consumed_digest.get(), consumed_bytes.data(), &consumed_size) != 1)
        throw std::runtime_error("stream input SHA-256 finalization failed");
    std::ostringstream consumed_text;
    consumed_text << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < consumed_size; ++i)
        consumed_text << std::setw(2) << static_cast<unsigned int>(consumed_bytes[i]);
    if (consumed_text.str() != dataset_hash)
        throw std::runtime_error("stream bytes changed between hashing and parsing");

    struct stat final_stat {};
    if (fstat(input_fd, &final_stat) != 0 || final_stat.st_size < 0 ||
        initial_stat.st_dev != final_stat.st_dev || initial_stat.st_ino != final_stat.st_ino ||
        initial_stat.st_size != final_stat.st_size || input_bytes != static_cast<std::uintmax_t>(final_stat.st_size) ||
        initial_stat.st_mtim.tv_sec != final_stat.st_mtim.tv_sec ||
        initial_stat.st_mtim.tv_nsec != final_stat.st_mtim.tv_nsec ||
        initial_stat.st_ctim.tv_sec != final_stat.st_ctim.tv_sec ||
        initial_stat.st_ctim.tv_nsec != final_stat.st_ctim.tv_nsec)
        throw std::runtime_error("stream input changed during replay");
    if (sha256_fd(input_fd, static_cast<std::uintmax_t>(final_stat.st_size)) != dataset_hash)
        throw std::runtime_error("stream input changed during replay");
    output.commit();
    return decision_count;
}

void write_frozen_manifest(const std::string &path, std::string_view content) {
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0444);
    if (fd < 0) throw std::runtime_error("freeze manifest path already exists or cannot be created");
    bool open_fd = true;
    try {
        write_all_fd(fd, content);
        if (fchmod(fd, 0444) != 0 || fsync(fd) != 0)
            throw std::runtime_error("cannot persist frozen dataset manifest");
        const int close_status = close(fd);
        open_fd = false;
        if (close_status != 0) throw std::runtime_error("cannot close frozen dataset manifest");
    } catch (...) {
        if (open_fd) (void)close(fd);
        (void)unlink(path.c_str());
        throw;
    }
}

void append_audit_ledger(const std::string &path, std::string_view record) {
    const int fd = open(path.c_str(), O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC |
                        O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) throw std::runtime_error("cannot open dataset audit ledger");
    bool open_fd = true;
    bool locked = false;
    try {
        if (flock(fd, LOCK_EX) != 0) throw std::runtime_error("cannot lock dataset audit ledger");
        locked = true;
        struct stat ledger_stat {};
        if (fstat(fd, &ledger_stat) != 0 || !S_ISREG(ledger_stat.st_mode) || ledger_stat.st_size < 0 ||
            static_cast<std::uintmax_t>(ledger_stat.st_size) > MAX_INPUT_FILE_BYTES ||
            record.size() > MAX_RECORD_BYTES ||
            static_cast<std::uintmax_t>(ledger_stat.st_size) > MAX_INPUT_FILE_BYTES - record.size())
            throw std::runtime_error("dataset audit ledger size limit");
        if (ledger_stat.st_uid != geteuid() || (ledger_stat.st_mode & 0077) != 0)
            throw std::runtime_error("dataset audit ledger must be owner-only");
        if (ledger_stat.st_size > 0) {
            char last_byte = '\0';
            if (pread(fd, &last_byte, 1U, ledger_stat.st_size - 1) != 1 || last_byte != '\n')
                throw std::runtime_error("dataset audit ledger must end with a complete record");
        }
        write_all_fd(fd, record);
        if (fdatasync(fd) != 0) throw std::runtime_error("cannot persist dataset audit ledger");
        if (flock(fd, LOCK_UN) != 0) throw std::runtime_error("cannot unlock dataset audit ledger");
        locked = false;
        const int close_status = close(fd);
        open_fd = false;
        if (close_status != 0) throw std::runtime_error("cannot close dataset audit ledger");
    } catch (...) {
        if (locked) (void)flock(fd, LOCK_UN);
        if (open_fd) (void)close(fd);
        throw;
    }
}

Value load_single_json_file(const std::string &path) {
    (void)bounded_input_file_size(path);
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open JSON manifest");
    std::string line;
    if (!read_limited_line(in, line, MAX_RECORD_BYTES) || line.empty())
        throw std::runtime_error("manifest must contain one JSON record");
    std::string extra;
    if (read_limited_line(in, extra, MAX_RECORD_BYTES))
        throw std::runtime_error("manifest must contain exactly one JSON record");
    if (in.bad()) throw std::runtime_error("manifest read failure");
    if (!valid_utf8(line)) throw std::runtime_error("manifest is not valid UTF-8");
    return bdetect::json::Parser(line).parse();
}

std::string stable_file_sha256(const std::string &path) {
    (void)bounded_input_file_size(path);
    const std::string first = sha256_file(path);
    const std::string second = sha256_file(path);
    if (first != second) throw std::runtime_error("dataset changed while hashing: " + path);
    return first;
}

std::int64_t epoch_now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool is_sha256_hex(const std::string &value) {
    return value.size() == 64U && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

void freeze_dataset(const std::string &dev_path, const std::string &holdout_path,
                    const std::string &rules_path, const std::string &manifest_path) {
    if (same_file_or_path(dev_path, holdout_path) ||
        same_file_or_path(dev_path, rules_path) ||
        same_file_or_path(holdout_path, rules_path) ||
        same_file_or_path(manifest_path, dev_path) ||
        same_file_or_path(manifest_path, holdout_path) ||
        same_file_or_path(manifest_path, rules_path))
        throw std::runtime_error("freeze manifest and datasets must use separate files");
    const std::string rules_hash = stable_file_sha256(rules_path);
    const Rules rules = load_rules(rules_path);
    if (rules.sha256 != rules_hash || stable_file_sha256(rules_path) != rules_hash)
        throw std::runtime_error("rules changed while freezing dataset split");
    const std::uintmax_t dev_bytes = bounded_input_file_size(dev_path);
    const std::uintmax_t holdout_bytes = bounded_input_file_size(holdout_path);
    const std::string dev_hash = stable_file_sha256(dev_path);
    const std::string holdout_hash = stable_file_sha256(holdout_path);
    if (dev_hash == holdout_hash)
        throw std::runtime_error("development and holdout datasets must have different content");
    std::ostringstream manifest;
    manifest << "{\"schema_version\":\"bdetect.dataset_freeze.v1\","
             << "\"created_at_epoch_seconds\":" << epoch_now_seconds()
             << ",\"split_method\":\"separate_files\",\"ruleset_revision\":\""
             << escape(rules.revision) << "\",\"development_bytes\":" << dev_bytes
             << ",\"development_dataset_sha256\":\"" << dev_hash
             << "\",\"holdout_bytes\":" << holdout_bytes
             << ",\"holdout_dataset_sha256\":\"" << holdout_hash
             << "\",\"ruleset_sha256\":\"" << rules.sha256 << "\"}\n";
    write_frozen_manifest(manifest_path, manifest.str());
    std::cout << "{\"frozen\":true,\"development_dataset_sha256\":\"" << dev_hash
              << "\",\"holdout_dataset_sha256\":\"" << holdout_hash
              << "\",\"ruleset_sha256\":\"" << rules.sha256 << "\"}\n";
}

bool audit_frozen_dataset(const std::string &manifest_path, const std::string &dev_path,
                          const std::string &holdout_path, const std::string &rules_path,
                          const std::string &ledger_path) {
    for (const std::string *input : {&manifest_path, &dev_path, &holdout_path, &rules_path}) {
        if (same_file_or_path(ledger_path, *input))
            throw std::runtime_error("audit ledger must be separate from every input");
    }
    if (same_file_or_path(dev_path, holdout_path))
        throw std::runtime_error("development and holdout datasets must be separate files");
    const std::string manifest_hash = stable_file_sha256(manifest_path);
    const Value manifest = load_single_json_file(manifest_path);
    const auto &manifest_fields = object_value(manifest, "dataset freeze manifest");
    const std::set<std::string> allowed_fields = {
        "schema_version", "created_at_epoch_seconds", "split_method", "ruleset_revision",
        "development_bytes", "development_dataset_sha256", "holdout_bytes",
        "holdout_dataset_sha256", "ruleset_sha256"
    };
    for (const auto &[field, value] : manifest_fields) {
        (void)value;
        if (!allowed_fields.contains(field))
            throw std::runtime_error("unknown dataset freeze manifest field: " + field);
    }
    if (required_text(manifest, "schema_version") != "bdetect.dataset_freeze.v1" ||
        required_text(manifest, "split_method") != "separate_files")
        throw std::runtime_error("unsupported dataset freeze manifest");
    const std::string expected_dev = required_text(manifest, "development_dataset_sha256");
    const std::string expected_holdout = required_text(manifest, "holdout_dataset_sha256");
    const std::string expected_rules = required_text(manifest, "ruleset_sha256");
    const double *expected_dev_bytes_value = std::get_if<double>(&required(manifest, "development_bytes").data);
    const double *expected_holdout_bytes_value = std::get_if<double>(&required(manifest, "holdout_bytes").data);
    if (!expected_dev_bytes_value || !expected_holdout_bytes_value ||
        !std::isfinite(*expected_dev_bytes_value) || !std::isfinite(*expected_holdout_bytes_value) ||
        *expected_dev_bytes_value < 0 || *expected_holdout_bytes_value < 0 ||
        *expected_dev_bytes_value > static_cast<double>(MAX_INPUT_FILE_BYTES) ||
        *expected_holdout_bytes_value > static_cast<double>(MAX_INPUT_FILE_BYTES) ||
        std::floor(*expected_dev_bytes_value) != *expected_dev_bytes_value ||
        std::floor(*expected_holdout_bytes_value) != *expected_holdout_bytes_value)
        throw std::runtime_error("invalid file size in dataset freeze manifest");
    if (!is_sha256_hex(expected_dev) || !is_sha256_hex(expected_holdout) ||
        !is_sha256_hex(expected_rules) || expected_dev == expected_holdout)
        throw std::runtime_error("invalid SHA-256 in dataset freeze manifest");
    const double *created_at = std::get_if<double>(&required(manifest, "created_at_epoch_seconds").data);
    if (!created_at || !std::isfinite(*created_at) || *created_at < 0 ||
        *created_at > 9007199254740991.0 || std::floor(*created_at) != *created_at)
        throw std::runtime_error("invalid creation time in dataset freeze manifest");
    const std::uintmax_t dev_bytes = bounded_input_file_size(dev_path);
    const std::uintmax_t holdout_bytes = bounded_input_file_size(holdout_path);
    const std::string current_rules_hash = stable_file_sha256(rules_path);
    const Rules rules = load_rules(rules_path);
    if (rules.sha256 != current_rules_hash || stable_file_sha256(rules_path) != current_rules_hash)
        throw std::runtime_error("rules changed while auditing frozen dataset");
    const std::string dev_hash = stable_file_sha256(dev_path);
    const std::string holdout_hash = stable_file_sha256(holdout_path);
    const bool dev_matches = dev_hash == expected_dev &&
        static_cast<double>(dev_bytes) == *expected_dev_bytes_value;
    const bool holdout_matches = holdout_hash == expected_holdout &&
        static_cast<double>(holdout_bytes) == *expected_holdout_bytes_value;
    const bool rules_match = rules.sha256 == expected_rules &&
        required_text(manifest, "ruleset_revision") == rules.revision;
    const bool unchanged = dev_matches && holdout_matches && rules_match;
    if (stable_file_sha256(manifest_path) != manifest_hash)
        throw std::runtime_error("freeze manifest changed during audit");
    std::ostringstream ledger_record;
    ledger_record << "{\"schema_version\":\"bdetect.dataset_audit.v1\","
                  << "\"observed_at_epoch_seconds\":" << epoch_now_seconds()
                  << ",\"manifest_sha256\":\"" << manifest_hash
                  << "\",\"development\":{\"expected_sha256\":\"" << expected_dev
                  << "\",\"observed_sha256\":\"" << dev_hash << "\",\"matches\":"
                  << (dev_matches ? "true" : "false") << "},\"holdout\":{\"expected_sha256\":\""
                  << expected_holdout << "\",\"observed_sha256\":\"" << holdout_hash
                  << "\",\"matches\":" << (holdout_matches ? "true" : "false")
                  << "},\"ruleset\":{\"expected_sha256\":\"" << expected_rules
                  << "\",\"observed_sha256\":\"" << rules.sha256 << "\",\"matches\":"
                  << (rules_match ? "true" : "false") << "},\"status\":\""
                  << (unchanged ? "unchanged" : "modified") << "\"}\n";
    append_audit_ledger(ledger_path, ledger_record.str());
    std::cout << "{\"unchanged\":" << (unchanged ? "true" : "false")
              << ",\"audit_recorded\":true}\n";
    return unchanged;
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
            std::cout << "bdetect replay --input FILE --rules FILE --out FILE [--speed EVENT_TIME_MULTIPLIER] [--stats-out FILE] [--stream]\n"
                         "bdetect evaluate --pred FILE --labels CSV --report FILE [--csv-report FILE] [--html-report FILE]\n"
                         "bdetect analyze-rules --input DECISIONS --report FILE\n"
                         "bdetect dataset-freeze --dev FILE --holdout FILE --rules FILE --manifest NEW-FILE\n"
                         "bdetect dataset-audit --manifest FILE --dev FILE --holdout FILE --rules FILE --ledger FILE\n"
                         "bdetect rules-validate --file FILE\n"
                         "bdetect generate-fixtures --root SANDBOX --out NEW-DIR\n"
                         "bdetect explain --decision-id ID --input DECISIONS\n";
            return argc < 2 ? 2 : 0;
        }
        std::string command = argv[1];
        if (command == "dataset-freeze") {
            freeze_dataset(arg(argc, argv, "--dev"), arg(argc, argv, "--holdout"),
                           arg(argc, argv, "--rules"), arg(argc, argv, "--manifest"));
        } else if (command == "dataset-audit") {
            const bool unchanged = audit_frozen_dataset(arg(argc, argv, "--manifest"),
                arg(argc, argv, "--dev"), arg(argc, argv, "--holdout"),
                arg(argc, argv, "--rules"), arg(argc, argv, "--ledger"));
            if (!unchanged) return 1;
        } else if (command == "rules-validate") {
            (void)load_rules(arg(argc, argv, "--file"));
            puts("{\"valid\":true}");
        } else if (command == "generate-fixtures") {
            generate_fixtures(arg(argc, argv, "--out"), arg(argc, argv, "--root"));
        } else if (command == "replay") {
            const std::string rules_path = arg(argc, argv, "--rules");
            Rules rules = load_rules(rules_path);
            const std::string input_path = arg(argc, argv, "--input");
            const std::string output_path = arg(argc, argv, "--out");
            const std::string stats_path = arg(argc, argv, "--stats-out");
            bool stats_requested = false, stream_requested = false;
            for (int i = 2; i < argc; ++i)
                if (std::string(argv[i]) == "--stats-out") stats_requested = true;
                else if (std::string(argv[i]) == "--stream") stream_requested = true;
            if (stream_requested) {
                if (stats_requested)
                    throw std::runtime_error("--stats-out is not available with --stream");
                std::size_t speed_bytes = 0;
                const std::string speed_arg = arg(argc, argv, "--speed", "0");
                double speed = 0.0;
                try { speed = std::stod(speed_arg, &speed_bytes); }
                catch (...) { throw std::runtime_error("invalid replay speed"); }
                if (speed_bytes != speed_arg.size()) throw std::runtime_error("invalid replay speed");
                const std::size_t decisions = stream_replay(input_path, rules_path,
                                                             output_path, rules, speed);
                std::cout << "decisions=" << decisions << " simulation_only=true stream=true\n";
            } else {
            enforce_input_file_size(input_path);
            const std::string dataset_hash = sha256_file(input_path);
            auto input_events = load_events(input_path);
            if (sha256_file(input_path) != dataset_hash)
                throw std::runtime_error("input changed while replay was loading");
            const std::size_t input_event_count = input_events.size();
            IntakeIssues issues;
            auto events = normalize_events(input_events, rules, issues);
            std::vector<Event>().swap(input_events);
            std::size_t speed_bytes = 0;
            const std::string speed_arg = arg(argc, argv, "--speed", "0");
            double speed = 0.0;
            try { speed = std::stod(speed_arg, &speed_bytes); }
            catch (...) { throw std::runtime_error("invalid replay speed"); }
            if (speed_bytes != speed_arg.size()) throw std::runtime_error("invalid replay speed");
            pace_replay(events, speed);
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
                write_replay_stats(stats_path, input_event_count, decisions.size(),
                                   evaluation_duration_ns, std::move(decision_latency_ns));
            std::cout << "decisions=" << decisions.size() << " simulation_only=true\n";
            }
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
