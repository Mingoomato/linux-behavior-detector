# Portfolio review / 포트폴리오 검토 안내

## 문제와 제작 의도

관찰 이벤트를 설명 가능한 시간 창의 점수로 바꾸기. 이 저장소는 Linux 시스템 호출의 결과와 실패를 관측 가능한 계약으로 연결하는 교육용 구현입니다.

## 핵심 설계

Batch와 stream 경로는 입력 계약을 공유합니다. Stream은 최대 관찰 시각에서 허용 지연을 빼 watermark를 만들고, 열린 시각 bucket과 활성 창에 각각 상한을 둡니다. 결과에 입력과 ruleset hash 및 원본 이벤트 ID를 남겨 재현성을 확보합니다.

## 코드 검토 경로

1. [`src/bdetect.cpp`](../src/bdetect.cpp)의 CLI 진입점에서 자원 획득과 오류 반환을 찾습니다.
2. [코드 해설](CODE_WALKTHROUGH.md)에서 핵심 함수와 소유권을 따라갑니다.
3. [최신 검증 기록](VALIDATION_CHECKPOINT.md)과 [요구사항 추적표](REQUIREMENTS_TRACEABILITY.md)를 비교합니다.
4. [기술 질문](TECHNICAL_INTERVIEW.md)과 [정답 없는 실습](DEBUGGING_EXERCISES.md)으로 직접 설명·재현합니다.

검토 질문: 같은 초의 이벤트를 언제 확정하는가? 유실된 증거가 정상 판정으로 바뀌지 않도록 어떻게 처리하는가? 합성 라벨과 실제 탐지율은 왜 다른가?

## English

**Purpose:** Turn observed events into explainable window scores.

Batch and stream modes share an input contract. Streaming derives a watermark from maximum observed time minus allowed lateness and bounds pending buckets and active windows separately. Decisions retain dataset/ruleset hashes and source IDs for reproducibility.

Start with the linked source entry point, follow `CODE_WALKTHROUGH.md`, and compare the dated checkpoint with requirement traceability. Review questions: When is one event second finalized? How does missing evidence avoid becoming a benign verdict? Why do synthetic labels not establish detection accuracy?

The five study documents cover subsystem purpose, data/control flow, Linux interfaces, memory/resource lifetime, concurrency, security assumptions, failures and alternatives. Three reproduction exercises remain unsolved. Repository checks and the owner's demonstrated competence are tracked separately; neither AI assistance nor automated test completion establishes personal mastery.
