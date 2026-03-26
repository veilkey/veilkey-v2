# VeilKey v2 — Path-Based Reference System

## Motivation

v1 참조 체계의 문제:

```
VK:LOCAL:3c3d53ea    ← 해시 — 의미 불명, 어떤 vault의 무슨 시크릿인지 모름
VK:TEMP:ed694a5e     ← 마찬가지
```

v2 목표:

```
VK:host-lv/owner/password     ← vault, 그룹, 키가 한눈에 보임
VK:soulflow-lv/db/password
VK:host-lv/cloudflare/api-key
```

## Architecture — 변경하지 않는 것

VeilKey의 핵심 아키텍처는 유지한다:

```
VaultCenter (중앙 키 서버)
├── agentDEK 보유 (암호문 미보유)
├── resolve 시 LocalVault에서 암호문 가져와 복호화
│
├── LocalVault: host-lv (LXC 102)
│   └── 암호문 보유 (복호화 불가)
├── LocalVault: soulflow-lv (LXC 104)
│   └── 암호문 보유 (복호화 불가)
└── ...
```

이유:
- 암호문과 키의 물리적 분리 — 업계에서 유일한 구조
- vault별 독립 DEK — blast radius 최소화
- 3층 키 계층 — master password → KEK(메모리만) → agentDEK → ciphertext
- 서비스 LXC 독립 — VaultCenter 장애 시에도 LocalVault 캐시로 운영 가능

## Reference Format

### v1 (현재)

```
VK:{SCOPE}:{8-char-hash}

VK:LOCAL:3c3d53ea
VK:TEMP:ed694a5e
VK:SSH:abc12345
```

- SCOPE: LOCAL, TEMP, SSH
- 식별자: SHA256 해시 앞 8자

### v2 (경로 기반)

```
VK:{vault}/{group}/{key}

VK:host-lv/owner/password
VK:host-lv/owner/email
VK:host-lv/cloudflare/api-key
VK:host-lv/cloudflare/email
VK:host-lv/mailgun/api-key
VK:soulflow-lv/db/password
VK:soulflow-lv/mattermost/webhook-url
```

### Depth 규칙

3단계 고정: `{vault}/{group}/{key}`

| 단계 | 의미 | 예시 |
|------|------|------|
| vault | LocalVault 이름 | `host-lv`, `soulflow-lv`, `mailu-lv` |
| group | 서비스 또는 카테고리 | `owner`, `cloudflare`, `db`, `smtp` |
| key | 실제 시크릿 이름 | `password`, `api-key`, `email` |

### 네이밍 규칙

- 소문자 + 하이픈: `owner`, `api-key`, `db-password`
- vault 이름은 LocalVault 등록 시 설정한 `vault_name`과 일치
- group은 자유 (서비스명, 카테고리 등)
- key는 자유

### 예약어

- `_temp/` — 임시 시크릿 (TTL 있음, 기존 VK:TEMP 대체)
- `_ssh/` — SSH 키 (기존 VK:SSH 대체)

```
VK:host-lv/_temp/session-token     ← TTL 있는 임시값
VK:host-lv/_ssh/deploy-key         ← SSH 키
```

## Backward Compatibility

v1 해시 참조는 계속 작동한다:

```
VK:LOCAL:3c3d53ea   ← v1 (유지)
VK:host-lv/owner/password  ← v2 (신규)
```

resolve 우선순위:
1. `/` 포함 → v2 경로 기반 조회
2. `VK:LOCAL:` 또는 `VK:TEMP:` → v1 해시 기반 조회
3. 그 외 → 기존 fallback 로직

## Resolve Flow

```
veilkey-cli resolve VK:host-lv/owner/password
    │
    ▼ CLI
    GET /api/resolve/VK:host-lv/owner/password
    │
    ▼ VaultCenter
    1. 경로 파싱: vault=host-lv, path=owner/password
    2. vault에 해당하는 agent 조회 (vault_name=host-lv)
    3. agent의 LocalVault에서 암호문 가져옴
       GET https://{agent_ip}:{port}/api/cipher/{path}
    4. agentDEK로 복호화
    5. 평문 반환
```

## CLI Changes

### Secret Management

```bash
# v1
veilkey-cli secret add MAILGUN_API_KEY "value"
→ VK:LOCAL:3c3d53ea

# v2
veilkey-cli secret add host-lv/mailgun/api-key "value"
→ VK:host-lv/mailgun/api-key

# vault 생략 시 기본 vault 사용
veilkey-cli secret add mailgun/api-key "value"
→ VK:{default-vault}/mailgun/api-key
```

### Listing

```bash
# 전체
veilkey-cli secret list
[host-lv]
  VK:host-lv/owner/password
  VK:host-lv/owner/email
  VK:host-lv/cloudflare/api-key
  VK:host-lv/mailgun/api-key

[soulflow-lv]
  VK:soulflow-lv/db/password

# vault 지정
veilkey-cli secret list --vault host-lv

# group 지정
veilkey-cli secret list --vault host-lv --group cloudflare
  VK:host-lv/cloudflare/api-key
  VK:host-lv/cloudflare/email
```

### Resolve

```bash
veilkey-cli resolve VK:host-lv/owner/password
→ Ghdrhkdgh1@
```

### Config (.env)

```env
# v1
CLOUDFLARE_API_KEY=VK:LOCAL:d7af11a6

# v2
CLOUDFLARE_API_KEY=VK:host-lv/cloudflare/api-key
OWNER_PASSWORD=VK:host-lv/owner/password
SMTP_PASSWORD=VK:host-lv/smtp/password
DB_PASSWORD=VK:soulflow-lv/db/password
```

## Storage Changes

### token_refs table

```sql
-- v1
ref_canonical = "VK:LOCAL:3c3d53ea"
ref_scope     = "LOCAL"
ref_id        = "3c3d53ea"
secret_name   = "MAILGUN_API_KEY"

-- v2 (추가 컬럼)
ref_canonical = "VK:host-lv/mailgun/api-key"
ref_vault     = "host-lv"          -- NEW
ref_group     = "mailgun"          -- NEW
ref_key       = "api-key"          -- NEW
ref_path      = "mailgun/api-key"  -- NEW (group/key)
secret_name   = "MAILGUN_API_KEY"  -- 기존 호환용 유지
```

### Migration

기존 시크릿에 대해:
1. `secret_name`을 기반으로 `ref_path` 자동 생성
2. `MAILGUN_API_KEY` → `mailgun/api-key` (UPPER_SNAKE → lower-kebab)
3. `agent_hash` → `ref_vault` (vault 이름 매핑)
4. 기존 `ref_canonical` (VK:LOCAL:hash)은 alias로 유지

## PTY Masking

mask_map에 v2 경로 참조도 포함:

```
plaintext → VK:host-lv/owner/password    (v2)
plaintext → VK:LOCAL:3c3d53ea            (v1, 호환)
```

터미널 출력에서 평문이 나오면 v2 경로 형식으로 마스킹.

## Implementation Plan

### Phase 1: 경로 기반 resolve (VaultCenter + CLI)
- VaultCenter resolve 핸들러에 `/` 포함 ref 처리
- CLI resolve_candidates에 경로 기반 지원
- 기존 해시 참조 호환 유지

### Phase 2: 경로 기반 secret 생성
- `veilkey-cli secret add {vault}/{group}/{key}` 지원
- DB에 ref_vault, ref_group, ref_key 컬럼 추가
- promote 시 경로 기반 ref_canonical 생성

### Phase 3: Migration + 호환
- 기존 시크릿을 경로 기반으로 자동 마이그레이션
- v1 해시 참조 → v2 경로 참조 alias 매핑
- PTY mask_map에 양쪽 참조 모두 등록

### Phase 4: CLI UX
- `secret list` 경로 기반 트리 출력
- `secret list --vault --group` 필터링
- 기본 vault 설정 (`~/.veilkey/config`)
- tab completion
