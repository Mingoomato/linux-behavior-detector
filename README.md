# Linux Ransomware Behavior Detection Lab

[:kr: 한국어](#한국어) · [:us: English](#english)

## 한국어

### 제작 의도

`bdetect`는 파일 이벤트를 안전한 합성 JSONL로 재생하고, 시간 창의 행위 특징을 설명 가능한 규칙 점수로 바꾸는 Linux 보안 학습·연구 프로젝트입니다. 이벤트 검증, 순서/중복 처리, 시간 창 집계, 규칙 기여도, 판정 근거와 평가 지표가 어떻게 연결되는지 보여 줍니다. 실제 랜섬웨어를 실행하거나 사용자 파일을 읽고·변경·차단하지 않습니다. 프로세스 행위자를 추정하지 않으며 결과는 항상 `simulation_only=true`입니다.

현재 작업 트리에는 입력 파일 크기 상한, 선택형 CSV·HTML 평가 보고서, 시간순 판정 내역, 규칙 상관관계 요약, 개발/holdout 파일 고정·감사 기능, 설정된 lateness 안의 재정렬을 지원하는 메모리 제한 `replay --stream`이 있습니다. 이 추가 변경들은 아직 기술 검증을 거치지 않았으며, 아래의 과거 검증 기록은 이전 코드 상태에만 적용됩니다.

### 빌드 및 실행

빌드에는 C++20 컴파일러, CMake 3.16 이상, OpenSSL Crypto 개발 라이브러리가 필요합니다. CTest에는 Python 3도 필요합니다.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/bdetect rules-validate --file rules/baseline.json
tmp=$(mktemp -d)
mkdir "$tmp/sandbox"
./build/bdetect generate-fixtures --root "$tmp/sandbox" --out "$tmp/sandbox/generated"
./build/bdetect replay --input "$tmp/sandbox/generated/rapid-rewrite.ndjson" --rules rules/baseline.json --out "$tmp/decisions.ndjson"
./build/bdetect replay --input "$tmp/sandbox/generated/rapid-rewrite.ndjson" --rules rules/baseline.json --out "$tmp/stream-decisions.ndjson" --stream
./build/bdetect evaluate --pred "$tmp/decisions.ndjson" --labels "$tmp/sandbox/generated/labels.csv" --report "$tmp/metrics.json" --csv-report "$tmp/metrics.csv" --html-report "$tmp/timeline.html"
./build/bdetect analyze-rules --input "$tmp/decisions.ndjson" --report "$tmp/rule-correlation.json"
```

`evaluate`는 기존 JSON 지표 보고서를 유지하면서 CSV 지표·판정 타임라인과 한국어·영어 정적 HTML 혼동행렬·타임라인을 선택적으로 생성합니다. 보고서에는 원문 파일 경로를 넣지 않고 판정의 entity key, 시간 창, 정답·예측·결과와 제공된 점수를 포함합니다. CSV는 따옴표 처리와 CRLF 행 구분을 사용하며, CSV/HTML 타임라인은 최대 100,000행입니다. 결과는 합성 평가에 대한 시뮬레이션 기록이지 악성코드 판정이 아닙니다.

`analyze-rules`는 판정별 규칙 동시 활성화 표, Jaccard 유사도와 phi 계수를 `bdetect.rule_analysis.v1` JSON으로 요약합니다. 최대 1,000,000개 판정, 256개 규칙, 10,000,000개의 pair 업데이트로 제한합니다. 겹치는 시간 창은 독립 표본이 아니므로 이 수치는 기술 검토를 위한 설명 통계입니다. 이 도구는 규칙 가중치를 자동으로 변경하지 않습니다.

`replay --stream`은 JSONL을 한 레코드씩 읽고 event time 초 단위로 판정합니다. `lateness_tolerance_ms` 안의 제한된 역순 이벤트는 event-time watermark까지 보류해 시간순으로 재구성하고, watermark보다 오래된 이벤트는 출력 커밋 전에 거부합니다. 초 단위 timestamp이므로 1초 미만 허용치는 같은 초 안의 순서만 허용합니다. producer sequence 메타데이터는 여전히 거부하므로 sequence gap 분석에는 batch replay를 사용합니다. watermark 대기 큐는 최대 4,096개 이벤트·64 MiB, 활성 창은 최대 100,000개 이벤트·64 MiB, ID 캐시는 최대 100,000개입니다. 큐나 활성 창 한계를 넘긴 이벤트는 버리고 해당 host 판정을 이벤트 시각부터 window 길이까지 `unknown`으로 표시합니다. 입력을 먼저 해시한 뒤 같은 file descriptor로 스트리밍하며, 파일 변경을 감지하면 임시 결과를 삭제합니다. 성공한 경우에만 0600 임시 파일을 동기화하고 최종 경로로 원자적 rename을 수행합니다. `--stats-out`은 스트림 모드에서 사용할 수 없습니다. 이 watermark 구현은 추가된 뒤 아직 기술 검증되지 않았습니다.

유실 이벤트만 표시하는 watermark 마커도 최대 4,096개이며, 이 한계에 도달하면 결과 파일을 커밋하지 않고 중단합니다.

개발 데이터와 holdout 데이터는 별도의 파일로 준비한 뒤 `dataset-freeze`로 SHA-256과 ruleset SHA-256을 새 읽기 전용 manifest에 고정합니다. 이후 각 holdout 평가 전에 `dataset-audit`를 실행하면 manifest와 데이터/ruleset hash 비교 결과를 owner-only JSONL ledger에 추가합니다. 불일치도 ledger에 먼저 기록하고 종료 코드 1을 반환합니다. 이 기능은 데이터를 자동 분할하지 않으며, 로컬 파일 권한과 append 기록만으로 변조 방지나 데이터의 독립성을 증명하지 않습니다.

```sh
./build/bdetect dataset-freeze --dev development.ndjson --holdout holdout.ndjson --rules rules/baseline.json --manifest frozen-datasets.json
./build/bdetect dataset-audit --manifest frozen-datasets.json --dev development.ndjson --holdout holdout.ndjson --rules rules/baseline.json --ledger dataset-audit.jsonl
```

선택적인 Clang/libFuzzer JSON parser 타깃은 별도 빌드에서 실행할 수 있습니다. 이 타깃은 일반 실행 파일의 의존성에 포함되지 않습니다.

```sh
cmake -S . -B /tmp/bdetect-fuzz-build -DCMAKE_CXX_COMPILER=clang++ -DBDETECT_BUILD_FUZZER=ON
cmake --build /tmp/bdetect-fuzz-build --target bdetect-json-fuzz
/tmp/bdetect-fuzz-build/bdetect-json-fuzz -max_len=4096 -runs=100000 tests/fuzz_corpus
```

기본 재생은 빠른 오프라인 모드입니다. 선택적으로 `--speed 10`을 지정하면 event time 사이 간격을 10배속 monotonic 시계로 재생합니다. 예상 대기 시간이 1시간을 넘는 데이터는 거부합니다. 이 설정은 결과 점수에 영향을 주지 않습니다. RFC 3339 timezone offset을 정규화하며, 소수 초는 현재 초 단위 시간 창에서 버립니다. 각 판정은 설정 파일과 입력 파일의 SHA-256, 적용 규칙의 관측값·연산자·임계치·가중치 기여분, 원본 이벤트 ID를 기록합니다. 선택적으로 `--stats-out replay-stats.json`을 주면 판정 JSONL은 그대로 유지하면서 별도 `bdetect.replay_stats.v1`에 결정별 p50/p95/p99/max scoring 지연을 기록합니다. 입력 파싱, pacing, 직렬화 시간은 이 측정에서 제외됩니다.

### 경계와 검증

입력 파일 전체는 최대 512 MiB, JSONL 레코드는 최대 1 MiB, 결정 레코드는 최대 64 MiB, 한 판정의 rule evidence 문자열은 최대 32 MiB이며 전체 이벤트와 평가 판정은 각각 최대 1,000,000개입니다. ID·host·kind·path, host cardinality, 규칙 분석 pair-work에도 상한을 둡니다. Batch replay는 입력과 정규화 사본을 읽는 동안 함께 보유하고 점수화 전에 입력 사본을 해제합니다. Stream replay는 초당 큐, 활성 창, ID 캐시, 출력 크기에 상한을 두며 재정렬과 producer sequence 분석이 필요하면 batch mode를 사용합니다. Stream mode는 event time 초 단위 오름차순을 요구하는 오프라인 bounded-memory 파일 재생이며 실시간 collector나 다중 producer 서비스는 아닙니다. 이벤트 ID 중복, batch lateness 허용치 초과, 손상된 coverage는 안전하게 `unknown` 판정으로 떨어집니다. 공급원은 선택적으로 `producer_session_id`와 양의 안전 정수 `producer_sequence`를 함께 보낼 수 있습니다. host·source·session별 순서 공백이나 충돌은 batch replay에서 coverage를 degraded로 표시하고 `unknown` 판정에 반영하며, 일부 이벤트에만 시퀀스 정보가 있으면 누락 여부를 알 수 없어 보수적으로 unknown 처리합니다. 시퀀스 메타데이터가 전혀 없는 공급원의 결측 이벤트는 식별할 수 없습니다.

평가 라벨 CSV는 제한된 2열 입력이며 따옴표 안 쉼표·따옴표 이스케이프·줄바꿈을 지원합니다. Clang/libFuzzer·ASan·UBSan으로 JSON parser를 10만 회 실행한 선택 검증에서는 충돌이 없었습니다. 이 짧은 실행은 퍼징 완전성을 증명하지 않습니다. 합성 8개 정상 시나리오와 4개 의심 시나리오에서 혼동행렬을 확인하는 테스트도 실행 연결만 검증합니다. 같은 합성 자료에서 나온 TP/FP/TN/FN은 실제 랜섬웨어 탐지율의 증거가 아닙니다. 대표성 있는 실제 데이터, 반복 p95 기준선, importer/timestamp 퍼징, 스트림 큐·TTL 경계 사례, 개발/holdout 분리 검증은 아직 검증되지 않았습니다. 합성 이벤트 10만 건을 여러 결정 시점으로 나눈 한 번의 측정은 `docs/TEST_RESULTS.md`에 기록했으며 안정적인 성능 기준선은 아닙니다. 상세 상태는 [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md), 설계는 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)와 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)를 참고하세요.

## English

### Intent

`bdetect` is a Linux security learning and research lab. It replays safe synthetic file-event JSONL and turns time-window behavior features into explainable rule scores. The project demonstrates how validation, deduplication and reordering, window aggregation, rule contributions, evidence, and evaluation metrics fit together. It does not execute ransomware, read or modify user files, block access, or infer process attribution. Every decision is marked `simulation_only=true`.

The current working tree adds a total input-file size bound, optional CSV/HTML evaluation reports, a chronological decision timeline, rule co-activation analysis, development/holdout freeze and audit commands, and a memory-bounded `replay --stream` mode with bounded event-time reordering. These changes have not been technically verified; historical verification notes below apply only to the earlier code state.

### Build and run

Build requirements: a C++20 compiler, CMake 3.16 or newer, and the OpenSSL Crypto development library. CTest also requires Python 3.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/bdetect rules-validate --file rules/baseline.json
tmp=$(mktemp -d)
mkdir "$tmp/sandbox"
./build/bdetect generate-fixtures --root "$tmp/sandbox" --out "$tmp/sandbox/generated"
./build/bdetect replay --input "$tmp/sandbox/generated/rapid-rewrite.ndjson" --rules rules/baseline.json --out "$tmp/decisions.ndjson"
./build/bdetect replay --input "$tmp/sandbox/generated/rapid-rewrite.ndjson" --rules rules/baseline.json --out "$tmp/stream-decisions.ndjson" --stream
./build/bdetect evaluate --pred "$tmp/decisions.ndjson" --labels "$tmp/sandbox/generated/labels.csv" --report "$tmp/metrics.json" --csv-report "$tmp/metrics.csv" --html-report "$tmp/timeline.html"
./build/bdetect analyze-rules --input "$tmp/decisions.ndjson" --report "$tmp/rule-correlation.json"
```

`evaluate` preserves the existing JSON metrics report and can also emit a CSV metrics/timeline report and a Korean/English static HTML confusion-matrix/timeline report. Reports omit raw file paths and include the decision entity key, time window, actual/predicted labels, outcome, and score when present. CSV cells are quoted and records use CRLF line endings. CSV/HTML timelines are limited to 100,000 rows. These outputs describe a simulation evaluation, not a malware verdict.

`analyze-rules` summarizes per-decision rule co-activation, Jaccard similarity, and the phi coefficient as `bdetect.rule_analysis.v1` JSON. It is bounded to 1,000,000 decisions, 256 distinct rules, and 10,000,000 pair updates. Overlapping windows are dependent observations, so these values are descriptive review aids; the command never changes rule weights automatically.

`replay --stream` reads JSONL one record at a time and scores event-time seconds. It accepts bounded event-time disorder within `lateness_tolerance_ms`, buffers records until the event-time watermark, then emits endpoints in time order; an event older than the watermark aborts before output commit. Timestamps have whole-second precision, so sub-second lateness tolerances allow reordering only within the same second. Producer sequence metadata is still rejected; use batch replay for sequence-gap analysis. The watermark queue is capped at 4,096 events and 64 MiB; the active window is capped at 100,000 events and 64 MiB; the ID cache is capped at 100,000 entries. Events dropped at queue or active-window limits keep the affected host `unknown` through the dropped timestamp plus the configured window. The command hashes the input first, streams from the same file descriptor, and discards temporary output if a file change is detected. A successful run syncs a mode-0600 temporary file and atomically renames it to the target. `--stats-out` is unavailable in stream mode. This watermark implementation has not been technically verified.

Dropped-only watermark markers are capped at 4,096; reaching that limit aborts before publishing output.

Prepare development and holdout data as separate files. `dataset-freeze` creates a new read-only manifest with their exact SHA-256 values, sizes, and the validated rule-file hash. Before each holdout evaluation, `dataset-audit` compares those values and appends an owner-only JSONL record; a mismatch is recorded before the command returns status 1. This does not create the split and does not cryptographically prove that the holdout is independent or that a local ledger has not been rewritten. Keep the manifest and ledger in trusted version control or another protected location.

```sh
./build/bdetect dataset-freeze --dev development.ndjson --holdout holdout.ndjson --rules rules/baseline.json --manifest frozen-datasets.json
./build/bdetect dataset-audit --manifest frozen-datasets.json --dev development.ndjson --holdout holdout.ndjson --rules rules/baseline.json --ledger dataset-audit.jsonl
```

Replay is fast and offline by default. Optionally pass `--speed 10` to pace event-time intervals at 10x using monotonic deadlines. Runs whose scheduled wait would exceed one hour are rejected. Pacing does not change the decision set. RFC 3339 timezone offsets are normalized; fractional seconds are discarded because windows currently have one-second precision. Each decision records the SHA-256 of the exact rules and input files, each contributing rule's observed value/operator/threshold/weight, and source event IDs. Add `--stats-out replay-stats.json` to emit a separate `bdetect.replay_stats.v1` record with p50/p95/p99/max per-decision scoring latency; it leaves decision JSONL unchanged and excludes parsing, pacing, and serialization time.

### Boundaries and verification

Input files are limited to 512 MiB, event records to 1 MiB, decision records to 64 MiB, per-decision rule evidence strings to 32 MiB, and total events/evaluated predictions to 1,000,000. Event fields, host cardinality, rules, and correlation pair work are also bounded. Batch replay briefly retains both raw and normalized event vectors and releases the raw vector before scoring. Stream replay bounds the watermark queue, active window, ID cache, and output size; the stream now accepts configured bounded disorder but still rejects producer sequence metadata. It is an offline bounded-memory file replay, not a live collector or multi-producer service. Duplicate IDs, events beyond the configured lateness tolerance, and damaged coverage lead to rejection or `unknown` as documented. A producer may optionally include both `producer_session_id` and a positive safe-integer `producer_sequence`; batch replay uses this metadata. Gaps or collisions scoped by host, source, and session degrade coverage and make decisions unknown; mixed sequenced and unsequenced events for a host/source are also unknown because completeness cannot be established. Missing events cannot be detected when an upstream producer provides no sequence metadata.

The label evaluator accepts bounded two-column CSV, including commas, escaped quotes, and embedded newlines inside quoted fields. Tests exercise eight benign and four synthetic suspicious scenarios to check pipeline wiring. Their TP/FP/TN/FN counts are not evidence of real ransomware detection efficacy. Representative real datasets, repeated p95 baselines, stream boundary/TTL cases, importer/timestamp fuzzing, and a frozen development/holdout evaluation are still open. One synthetic 100,000-event multi-window run is recorded in `docs/TEST_RESULTS.md`; it is not a stable performance baseline. See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for status and design.

An optional Clang/libFuzzer JSON parser target can be built separately and does not add a runtime dependency to the normal executable:

```sh
cmake -S . -B /tmp/bdetect-fuzz-build -DCMAKE_CXX_COMPILER=clang++ -DBDETECT_BUILD_FUZZER=ON
cmake --build /tmp/bdetect-fuzz-build --target bdetect-json-fuzz
/tmp/bdetect-fuzz-build/bdetect-json-fuzz -max_len=4096 -runs=100000 tests/fuzz_corpus
```

A selected 100,000-run parser campaign with Clang libFuzzer, ASan, and UBSan completed without a crash. This short run does not prove fuzz completeness. Representative real datasets, repeated p95 baselines, stream boundary/TTL cases, longer importer/timestamp fuzzing, and a frozen development/holdout evaluation are still open. See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for status and design.
