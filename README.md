# Linux Ransomware Behavior Detection Lab

[:kr: 한국어](#한국어) · [:us: English](#english)

## 한국어

`bdetect`는 합성 `event.v1` JSONL을 재생하고 고정 UTC 시간 구간에서 설명 가능한 규칙을 적용하는 연구·학습용 분류기입니다. 목적은 이벤트 검증, 특징 집계, 판정 근거, 혼동행렬을 추적하는 것입니다. 실제 랜섬웨어를 실행하지 않고 사용자 파일을 바꾸거나 차단하지 않으며 프로세스 행위자를 추정하지 않습니다. 모든 판정은 `simulation_only=true`입니다.

### 빌드 및 실행

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./build/bdetect rules-validate --file rules/baseline.json
./build/bdetect replay --input fixtures/sample.ndjson --rules rules/baseline.json --out decisions.ndjson
```

독립 C++20 프로그램이며 추가 런타임 라이브러리는 필요하지 않습니다. 입력 레코드는 1 MiB, 이벤트 수는 1,000,000개로 제한합니다. `ctest --test-dir build --output-on-failure`는 합성 fixture 스모크를 실행합니다.

### 검증 및 구현 경계

현재 Release 빌드와 합성 fixture CTest 1/1이 통과했고, 별도 ASan/UBSan 스모크도 통과 기록이 있습니다. 8개 benign 및 4개 synthetic suspicious fixture에서 TP=4, FP=0, TN=8, FN=0이 나왔지만 fixture와 라벨이 함께 생성되므로 실제 탐지 성능의 증거가 아닙니다.

현재 코드는 host별 고정 UTC 구간을 사용합니다. 지연 허용치에 따른 순서 정리, 최소 표본 계산 전 중복 제거, 슬라이딩 윈도, 규칙별 가중치 완전 반영, 개발/검증 데이터 분리와 해시 고정, 원시 경로 가명화, 대규모 스트레스 측정은 아직 완료되지 않았습니다. 이 프로젝트는 안티랜섬웨어 제품이 아니며 실제 행위 판정을 보장하지 않습니다.

세부 근거는 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)를 참고하세요.

## English

`bdetect` replays synthetic `event.v1` JSONL and applies deterministic, explainable rules to host-level windows. It never executes malware, modifies user files, blocks access, or claims process attribution. Every decision is marked `simulation_only`.

## Build and run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./build/bdetect rules-validate --file rules/baseline.json
./build/bdetect replay --input fixtures/sample.ndjson --rules rules/baseline.json --out decisions.ndjson
```

The implementation is self-contained C++20 and has no third-party runtime dependency.

## Capabilities and limits

The importer validates required event fields and reports line numbers for malformed input. Replay groups by `host_id` and fixed 30-second buckets, counts unique modified/renamed/deleted paths and extension diversity, and emits source event IDs and rule reasons. Missing or degraded coverage yields `unknown`. PID/actor data is not used for attribution.

The current implementation does not reorder late events, deduplicate input records before minimum-sample checks, load arbitrary per-rule operators/weights, implement a maximum-lateness buffer, or split development/holdout datasets automatically. Window boundaries use UTC epoch seconds and fixed buckets rather than a rolling window. Synthetic fixture generation writes only event records and refuses an existing output directory; it does not create file workloads.

Run `ctest --test-dir build --output-on-failure` to generate and replay eight benign and four synthetic suspicious scenarios. The smoke result is 4 true positives, 0 false positives, 8 true negatives, and 0 false negatives on those generated labels. These figures confirm fixture/rule wiring only; they are not a measured malware detection rate.

No detection-quality or performance results are claimed. This is a lab classifier, not a malware detector or endpoint protection product.
