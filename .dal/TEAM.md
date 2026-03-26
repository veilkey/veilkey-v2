# VeilKey v2 Dal Team

## Team Members

| Dal | Role | Player | auto_task | Interval |
|-----|------|--------|-----------|----------|
| **leader** | leader | claude | - | - |
| **dev** | member | claude (go) | - | - |
| **improver** | member | claude | - | - |
| **verifier** | member | claude (go) | go test + cargo test | 1h |
| **ci-worker** | member | claude | - | - |
| **marketing** | member | claude | - | - |
| **tech-writer** | member | claude | - | - |

## Workflow: leader -> dev -> improver -> verifier

```
leader ──assign──> dev ──implement──> improver ──refine──> verifier ──validate──> leader
  │                                                                                 │
  └─────────────────────── merge / reject <─────────────────────────────────────────┘
```

### 1. Leader (계획 및 할당)

- Issue/feature를 dal 단위 task로 분해
- `dalcli-leader assign --dal dev` 로 개발 할당
- 최종 PR 리뷰 및 머지 결정

### 2. Dev (구현)

- Go/Rust 기능 개발, 버그 수정
- 테스트 코드 작성 (go test, cargo test)
- 구현 완료 후 improver에게 전달

### 3. Improver (개선)

- 코드 품질 리뷰 (naming, structure, duplication)
- 보안 강화 (crypto/rand, AES-256-GCM 준수)
- 테스트 커버리지 보강
- 리팩토링 후 verifier에게 전달

### 4. Verifier (검증)

- `go vet ./... && go test ./...` 실행
- `cargo test` 실행 (veil-cli)
- 보안 감사 (split storage, secret handling)
- auto_task: 1시간 주기 자동 검증
- 전부 통과 시 leader에게 PASS 보고

## Quality Gates

PR 머지 전 필수 조건:

1. dev가 테스트 포함 구현 완료
2. improver가 코드 품질/보안 개선 완료
3. verifier가 전체 테스트 PASS 확인
4. leader가 최종 리뷰 승인
5. CI pipeline 그린
