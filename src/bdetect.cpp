#include "bdetect/json.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using bdetect::json::Value;
constexpr std::size_t MAX_RECORD_BYTES = 1024U * 1024U;
constexpr std::size_t MAX_EVENT_COUNT = 1000000U;
struct Event {
    std::string id, host, kind, path, observed, coverage;
    std::int64_t epoch = 0;
};
struct Rules {
    std::string revision = "baseline-1";
    int window = 30, lateness_ms = 2000, max_entities = 10000;
    int min_events = 10, cutoff = 60;
    int rewrite = 40, rename = 30, deletion = 30, extension_types = 8;
};
struct Decision {
    std::string id, host, label, start, end;
    int score = 0;
    std::vector<std::string> reasons, event_ids;
    std::vector<std::string> unknown;
};

std::string escape(const std::string &s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') o << '\\' << static_cast<char>(c);
        else if (c == '\n') o << "\\n";
        else if (c >= 0x20U) o << static_cast<char>(c);
    }
    return o.str();
}

const Value &required(const Value &v, const char *key) {
    const Value *p = v.get(key);
    if (!p) throw std::runtime_error(std::string("missing field: ") + key);
    return *p;
}

std::int64_t parse_time(const std::string &s) {
    std::tm tm{};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d",
                    &year, &month, &day, &hour, &minute, &second) != 6)
        throw std::runtime_error("invalid observed_at");
    tm.tm_year = year - 1900; tm.tm_mon = month - 1; tm.tm_mday = day;
    tm.tm_hour = hour; tm.tm_min = minute; tm.tm_sec = second;
    return static_cast<std::int64_t>(timegm(&tm));
}

bool read_limited_line(std::istream &in, std::string &line) {
    line.clear();
    char c = '\0';
    bool consumed = false;
    while (in.get(c)) {
        consumed = true;
        if (c == '\n') return true;
        if (line.size() == MAX_RECORD_BYTES)
            throw std::runtime_error("JSON record too large");
        line.push_back(c);
    }
    if (in.bad()) throw std::runtime_error("input read failure");
    return consumed;
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
    std::ifstream in(file, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open input: " + file);
    std::vector<Event> events;
    std::string line;
    std::size_t line_no = 0;
    for (;;) {
        try {
            if (!read_limited_line(in, line)) break;
        } catch (const std::exception &ex) {
            throw std::runtime_error("line " + std::to_string(line_no + 1U) + ": " + ex.what());
        }
        ++line_no;
        if (line.empty()) continue;
        try {
            if (!valid_utf8(line)) throw std::runtime_error("invalid UTF-8");
            Value root = bdetect::json::Parser(line).parse();
            if (required(root, "schema_version").string_or() != "event.v1")
                throw std::runtime_error("unsupported schema_version");
            Event e;
            e.id = required(root, "event_id").string_or();
            e.host = required(root, "host_id").string_or();
            e.kind = required(root, "kind").string_or();
            e.observed = required(root, "observed_at").string_or();
            e.epoch = parse_time(e.observed);
            const Value &target = required(root, "target");
            e.path = required(target, "path").string_or();
            const Value *coverage = root.get("coverage");
            e.coverage = coverage && coverage->get("state")
                ? coverage->get("state")->string_or("unknown") : "unknown";
            if (e.id.empty() || e.host.empty() || e.kind.empty() || e.path.empty())
                throw std::runtime_error("empty required event field");
            if (e.id.size() > 256U || e.host.size() > 256U || e.kind.size() > 128U ||
                e.path.size() > 4096U)
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
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    Value v = bdetect::json::Parser(content).parse();
    if (required(v, "schema_version").string_or() != "rules.v1")
        throw std::runtime_error("rules schema must be rules.v1");
    Rules r;
    if (const Value *p = v.get("revision")) r.revision = p->string_or(r.revision);
    auto integer = [&v](const char *key, int fallback, int low, int high) {
        const Value *p = v.get(key);
        if (!p) return fallback;
        const double *number = std::get_if<double>(&p->data);
        if (!number || !std::isfinite(*number) || std::floor(*number) != *number ||
            *number < low || *number > high)
            throw std::runtime_error(std::string("invalid rule integer: ") + key);
        return static_cast<int>(*number);
    };
    r.window = integer("window_seconds", r.window, 10, 60);
    if (r.window != 10 && r.window != 30 && r.window != 60)
        throw std::runtime_error("window_seconds must be 10, 30, or 60");
    r.lateness_ms = integer("lateness_tolerance_ms", r.lateness_ms, 0, 60000);
    r.max_entities = integer("max_entities", r.max_entities, 1, 100000);
    r.min_events = integer("min_event_count", r.min_events, 1, 100000);
    r.cutoff = integer("score_cutoff", r.cutoff, 1, 1000);
    r.rewrite = integer("rewrite_threshold", r.rewrite, 1, 100000);
    r.rename = integer("rename_threshold", r.rename, 1, 100000);
    r.deletion = integer("delete_threshold", r.deletion, 1, 100000);
    r.extension_types = integer("extension_types_threshold", r.extension_types, 1, 100000);
    if (r.min_events < 1 || r.min_events > 100000 ||
        r.cutoff < 1 || r.cutoff > 1000 || r.rewrite < 1 || r.rename < 1 || r.deletion < 1)
        throw std::runtime_error("rules threshold out of range");
    return r;
}

using IntakeIssues = std::map<std::string, std::vector<std::string>>;

void add_issue(IntakeIssues &issues, const std::string &host, const std::string &reason) {
    auto &items = issues[host];
    if (std::find(items.begin(), items.end(), reason) == items.end()) items.push_back(reason);
}

bool same_event(const Event &a, const Event &b) {
    return a.host == b.host && a.kind == b.kind && a.path == b.path &&
           a.observed == b.observed && a.coverage == b.coverage;
}

std::vector<Event> normalize_events(const std::vector<Event> &input, const Rules &r,
                                    IntakeIssues &issues) {
    std::map<std::string_view, std::int64_t> latest_by_host;
    std::map<std::string_view, std::size_t> by_id;
    std::vector<Event> accepted;
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
                if (first.host != event.host) accepted.push_back(event);
            }
            continue;
        }
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
    std::stable_sort(accepted.begin(), accepted.end(), [](const Event &a, const Event &b) {
        if (a.host != b.host) return a.host < b.host;
        if (a.epoch != b.epoch) return a.epoch < b.epoch;
        return a.id < b.id;
    });
    return accepted;
}

std::vector<Decision> evaluate(const std::vector<Event> &events, const Rules &r,
                               const IntakeIssues &issues) {
    std::map<std::string, std::vector<const Event *>> by_host;
    for (const auto &e : events) by_host[e.host].push_back(&e);
    std::vector<Decision> out;
    for (const auto &[host, host_events] : by_host) {
        std::size_t left = 0;
        std::set<std::int64_t> endpoints;
        for (const Event *event : host_events) endpoints.insert(event->epoch);
        for (std::int64_t end : endpoints) {
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
            bool degraded = false;
            for (std::size_t i = left; i < right; ++i) {
                const Event *e = host_events[i];
                ids.insert(e->id);
                if (e->coverage != "healthy" && e->coverage != "observed") degraded = true;
                if (e->kind == "file.modified") modified.insert(e->path);
                if (e->kind == "path.renamed" || e->kind == "file.renamed" || e->kind == "file.moved_to") renamed.insert(e->path);
                if (e->kind == "file.deleted") deleted.insert(e->path);
                std::size_t slash = e->path.find_last_of('/');
                std::size_t dot = e->path.find_last_of('.');
                if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
                    extensions.insert(e->path.substr(dot));
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
                if (modified.size() >= static_cast<std::size_t>(r.rewrite)) {
                    d.score += 60; d.reasons.push_back("R-MASS-REWRITE");
                }
                if (renamed.size() >= static_cast<std::size_t>(r.rename)) {
                    d.score += 60; d.reasons.push_back("R-MASS-RENAME");
                }
                if (deleted.size() >= static_cast<std::size_t>(r.deletion)) {
                    d.score += 60; d.reasons.push_back("R-MASS-DELETE");
                }
                if (extensions.size() >= static_cast<std::size_t>(r.extension_types)) {
                    d.score += 20; d.reasons.push_back("R-EXTENSION-DIVERSITY");
                }
                d.label = d.score >= r.cutoff ? "suspicious" : "benign";
            }
            out.push_back(std::move(d));
        }
    }
    return out;
}

void write_decisions(const std::string &path, const std::vector<Decision> &ds, const Rules &r) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot open output");
    for (const auto &d : ds) {
        const bool degraded = std::any_of(d.unknown.begin(), d.unknown.end(),
            [](const std::string &reason) { return reason != "insufficient_events"; });
        out << "{\"schema_version\":\"decision.v1\",\"decision_id\":\"" << escape(d.id)
            << "\",\"ruleset_revision\":\"" << escape(r.revision) << "\",\"entity_key\":\""
            << escape(d.host) << "\",\"window_start\":\"" << d.start << "\",\"window_end\":\""
            << d.end << "\",\"score\":" << d.score << ",\"decision\":\"" << d.label
            << "\",\"simulation_only\":true,\"coverage\":\""
            << (degraded ? "degraded" : "observed") << "\",\"source_event_ids\":[";
        for (std::size_t i = 0; i < d.event_ids.size(); ++i) {
            if (i) out << ',';
            out << '"' << escape(d.event_ids[i]) << '"';
        }
        out << "],\"reasons\":[";
        for (std::size_t i = 0; i < d.reasons.size(); ++i) {
            if (i) out << ',';
            out << '"' << d.reasons[i] << '"';
        }
        out << "],\"unknown_fields\":[";
        for (std::size_t i = 0; i < d.unknown.size(); ++i) {
            if (i) out << ',';
            out << '"' << d.unknown[i] << '"';
        }
        out << "]}\n";
    }
}

void validate_events(const std::string &file) {
    auto events = load_events(file);
    std::cout << "{\"valid\":true,\"records\":" << events.size() << "}\n";
}

void evaluate_labels(const std::string &pred_path, const std::string &labels_path,
                     const std::string &report) {
    std::map<std::string, std::string> labels;
    std::ifstream l(labels_path);
    if (!l) throw std::runtime_error("cannot open labels");
    std::string line;
    while (std::getline(l, line)) {
        if (line.empty() || line.rfind("entity_key,", 0) == 0) continue;
        auto comma = line.find(',');
        if (comma == std::string::npos) throw std::runtime_error("bad labels CSV");
        labels[line.substr(0, comma)] = line.substr(comma + 1);
    }
    std::ifstream p(pred_path);
    if (!p) throw std::runtime_error("cannot open predictions");
    int tp=0, fp=0, tn=0, fn=0, unknown=0;
    while (std::getline(p, line)) {
        Value v = bdetect::json::Parser(line).parse();
        std::string key = required(v, "entity_key").string_or();
        std::string pred = required(v, "decision").string_or();
        auto it = labels.find(key);
        if (it == labels.end()) throw std::runtime_error("missing label for " + key);
        if (pred == "unknown") { ++unknown; continue; }
        bool actual = it->second == "suspicious";
        bool detected = pred == "suspicious";
        if (actual && detected) ++tp; else if (actual) ++fn;
        else if (detected) ++fp; else ++tn;
    }
    auto metric = [](int n, int d) { return d ? std::to_string(static_cast<double>(n) / d) : "N/A"; };
    std::ofstream out(report);
    if (!out) throw std::runtime_error("cannot write report");
    out << "{\"tp\":"<<tp<<",\"fp\":"<<fp<<",\"tn\":"<<tn<<",\"fn\":"<<fn
        <<",\"unknown\":"<<unknown<<",\"precision\":\""<<metric(tp,tp+fp)
        <<"\",\"recall\":\""<<metric(tp,tp+fn)<<"\",\"fpr\":\""<<metric(fp,fp+tn)
        <<"\",\"fnr\":\""<<metric(fn,fn+tp)<<"\"}\n";
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
        std::string kind = name == "mass-rename" ? "file.renamed" :
                           name == "mass-delete" ? "file.deleted" : "file.modified";
        for (int i = 0; i < count; ++i) {
            const char *ts = "2026-10-09T12:00:00Z";
            std::string path = "/sandbox/" + name + "/item" + std::to_string(i) +
                               (i % 2 ? ".dat" : ".txt");
            file << "{\"schema_version\":\"event.v1\",\"event_id\":\"" << name << "-"
                 << i << "\",\"source\":\"fixture\",\"host_id\":\"" << host
                 << "\",\"observed_at\":\"" << ts << "\",\"kind\":\"" << kind
                 << "\",\"severity\":\"info\",\"target\":{\"path\":\"" << path
                 << "\"},\"actor\":{\"pid\":null,\"attribution\":\"unknown\"},"
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
            std::cout << "bdetect replay --input FILE --rules FILE --out FILE\n"
                         "bdetect evaluate --pred FILE --labels CSV --report FILE\n"
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
            auto input_events = load_events(arg(argc, argv, "--input"));
            IntakeIssues issues;
            auto events = normalize_events(input_events, rules, issues);
            auto decisions = evaluate(events, rules, issues);
            write_decisions(arg(argc, argv, "--out"), decisions, rules);
            std::cout << "decisions=" << decisions.size() << " simulation_only=true\n";
        } else if (command == "evaluate") {
            evaluate_labels(arg(argc, argv, "--pred"), arg(argc, argv, "--labels"),
                            arg(argc, argv, "--report"));
        } else if (command == "explain") {
            std::string wanted = arg(argc, argv, "--decision-id");
            std::ifstream in(arg(argc, argv, "--input"));
            if (!in) throw std::runtime_error("cannot open decisions");
            std::string line; bool found=false;
            while (std::getline(in,line)) {
                Value v=bdetect::json::Parser(line).parse();
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
