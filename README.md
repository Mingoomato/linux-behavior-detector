# Linux Ransomware Behavior Detection Lab

[:kr: 한국어](#한국어) · [:us: English](#english)

## 한국어

### 제작 의도

`bdetect`는 파일 이벤트를 안전한 합성 JSONL로 재생하고, 시간 창의 행위 특징을 설명 가능한 규칙 점수로 바꾸는 Linux 보안 학습·연구 프로젝트입니다. 이벤트 검증, 순서/중복 처리, 시간 창 집계, 규칙 기여도, 판정 근거와 평가 지표가 어떻게 연결되는지 보여 줍니다. 실제 랜섬웨어를 실행하거나 사용자 파일을 읽고·변경·차단하지 않습니다. 프로세스 행위자를 추정하지 않으며 결과는 항상 `simulation_only=true`입니다.

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
```

선택적인 Clang/libFuzzer JSON parser 타깃은 별도 빌드에서 실행할 수 있습니다. 이 타깃은 일반 실행 파일의 의존성에 포함되지 않습니다.

```sh
cmake -S . -B /tmp/bdetect-fuzz-build -DCMAKE_CXX_COMPILER=clang++ -DBDETECT_BUILD_FUZZER=ON
cmake --build /tmp/bdetect-fuzz-build --target bdetect-json-fuzz
/tmp/bdetect-fuzz-build/bdetect-json-fuzz -max_len=4096 -runs=100000 tests/fuzz_corpus
```

기본 재생은 빠른 오프라인 모드입니다. 선택적으로 `--speed 10`을 지정하면 event time 사이 간격을 10배속 monotonic 시계로 재생합니다. 예상 대기 시간이 1시간을 넘는 데이터는 거부합니다. 이 설정은 결과 점수에 영향을 주지 않습니다. RFC 3339 timezone offset을 정규화하며, 소수 초는 현재 초 단위 시간 창에서 버립니다. 각 판정은 설정 파일과 입력 파일의 SHA-256, 적용 규칙의 관측값·연산자·임계치·가중치 기여분, 원본 이벤트 ID를 기록합니다.

### 경계와 검증

입력 JSONL 레코드는 최대 1 MiB, 결정 레코드는 최대 64 MiB, 전체 이벤트는 최대 1,000,000개이며 ID·host·kind·path와 host cardinality에도 상한을 둡니다. 입력 데이터 전체와 정규화된 사본을 메모리에 보관하는 오프라인 구현이라 초대형 스트리밍 분석기는 아닙니다. 이벤트 ID 중복, 지연 허용치 초과, 손상된 coverage는 안전하게 `unknown` 판정으로 떨어집니다. 공급원은 선택적으로 `producer_session_id`와 양의 안전 정수 `producer_sequence`를 함께 보낼 수 있습니다. host·source·session별 순서 공백이나 충돌은 coverage를 degraded로 표시하고 `unknown` 판정에 반영하며, 일부 이벤트에만 시퀀스 정보가 있으면 누락 여부를 알 수 없어 보수적으로 unknown 처리합니다. 시퀀스 메타데이터가 전혀 없는 공급원의 결측 이벤트는 식별할 수 없습니다.

평가 라벨 CSV는 제한된 2열 입력이며 따옴표 안 쉼표·따옴표 이스케이프·줄바꿈을 지원합니다. Clang/libFuzzer·ASan·UBSan으로 JSON parser를 10만 회 실행한 선택 검증에서는 충돌이 없었습니다. 이 짧은 실행은 퍼징 완전성을 증명하지 않습니다. 합성 8개 정상 시나리오와 4개 의심 시나리오에서 혼동행렬을 확인하는 테스트도 실행 연결만 검증합니다. 같은 합성 자료에서 나온 TP/FP/TN/FN은 실제 랜섬웨어 탐지율의 증거가 아닙니다. 대표성 있는 실제 데이터, p95 부하, 장시간 퍼징 및 개발/holdout 분리 검증은 아직 완료되지 않았습니다. 상세 상태는 [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md), 설계는 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)와 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)를 참고하세요.

## English

### Intent

`bdetect` is a Linux security learning and research lab. It replays safe synthetic file-event JSONL and turns time-window behavior features into explainable rule scores. The project demonstrates how validation, deduplication and reordering, window aggregation, rule contributions, evidence, and evaluation metrics fit together. It does not execute ransomware, read or modify user files, block access, or infer process attribution. Every decision is marked `simulation_only=true`.

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
```

Replay is fast and offline by default. Optionally pass `--speed 10` to pace event-time intervals at 10x using monotonic deadlines. Runs whose scheduled wait would exceed one hour are rejected. Pacing does not change the decision set. RFC 3339 timezone offsets are normalized; fractional seconds are discarded because windows currently have one-second precision. Each decision records the SHA-256 of the exact rules and input files, each contributing rule's observed value/operator/threshold/weight, and source event IDs.

### Boundaries and verification

Input records are limited to 1 MiB, decision records to 64 MiB, total events to 1,000,000, and event fields, host cardinality, and rules are bounded. The offline implementation keeps both the input corpus and a normalized copy in memory; it is not a large-scale streaming analyzer. Duplicate IDs, events outside the lateness tolerance, and damaged coverage lead to `unknown`. A producer may optionally include both `producer_session_id` and a positive safe-integer `producer_sequence`. Gaps or collisions scoped by host, source, and session degrade coverage and make decisions unknown; mixed sequenced and unsequenced events for a host/source are also unknown because completeness cannot be established. Missing events cannot be detected when an upstream producer provides no sequence metadata.

The label evaluator accepts bounded two-column CSV, including commas, escaped quotes, and embedded newlines inside quoted fields. Tests exercise eight benign and four synthetic suspicious scenarios to check pipeline wiring. Their TP/FP/TN/FN counts are not evidence of real ransomware detection efficacy. Representative real datasets, p95 load measurements, fuzzing, and a frozen development/holdout evaluation are still open. See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for status and design.

An optional Clang/libFuzzer JSON parser target can be built separately and does not add a runtime dependency to the normal executable:

```sh
cmake -S . -B /tmp/bdetect-fuzz-build -DCMAKE_CXX_COMPILER=clang++ -DBDETECT_BUILD_FUZZER=ON
cmake --build /tmp/bdetect-fuzz-build --target bdetect-json-fuzz
/tmp/bdetect-fuzz-build/bdetect-json-fuzz -max_len=4096 -runs=100000 tests/fuzz_corpus
```

A selected 100,000-run parser campaign with Clang libFuzzer, ASan, and UBSan completed without a crash. This short run does not prove fuzz completeness. Representative real datasets, p95 load measurements, longer fuzzing, and a frozen development/holdout evaluation are still open. See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for status and design.
