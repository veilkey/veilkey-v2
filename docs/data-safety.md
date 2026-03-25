# Data Safety & Disaster Recovery

## 핵심 원칙

**VaultCenter의 data 디렉토리는 모든 시크릿의 마스터 저장소다.**
이 디렉토리가 손실되면 모든 암호화된 시크릿은 영구적으로 복구 불가능하다.

## 파일 구조

```
data/vaultcenter/
├── veilkey.db          # 암호화된 SQLCipher DB (모든 시크릿, vault, agent 정보)
├── veilkey.db-shm      # SQLite shared memory
├── veilkey.db-wal      # SQLite write-ahead log
├── salt                # KEK 파생용 salt (32 bytes, init 시 1회 생성)
├── certs/              # TLS 인증서
├── chain/              # CometBFT 체인 데이터
└── bulk-apply/         # 일괄 변경 템플릿
```

## 절대 하지 말 것

| 금지 행위 | 결과 |
|-----------|------|
| `rm -rf data/vaultcenter/` | **전체 시크릿 영구 손실** |
| `mv data/vaultcenter data/...` + `init --root` | 새 KEK로 새 DB 생성 → 이전 시크릿 접근 불가 |
| 다른 버전 바이너리로 DB 열기 | DB key 파생 방식이 다르면 unlock 실패 |
| salt 파일 삭제/변경 | KEK 파생 불가 → unlock 영구 실패 |
| 여러 VaultCenter가 같은 data 디렉토리 공유 | DB 손상 |

## 백업 전략

### 필수 백업 대상
1. `veilkey.db` + `veilkey.db-shm` + `veilkey.db-wal` (항상 3개 함께)
2. `salt` 파일
3. `chain/` 디렉토리 (CometBFT 상태)
4. `certs/` 디렉토리
5. **바이너리 버전** (DB 호환성 보장을 위해)

### 백업 명령
```bash
# LXC 스냅샷 (권장)
pct snapshot <vmid> backup-$(date +%Y%m%d)

# 파일 레벨 백업 (서비스 정지 후)
docker compose stop vaultcenter
tar czf vaultcenter-backup-$(date +%Y%m%d).tar.gz data/vaultcenter/
docker compose start vaultcenter

# 주의: WAL 모드에서 hot backup은 veilkey.db만 복사하면 불완전
```

### 자동 백업
```bash
# /etc/cron.d/veilkey-backup
0 3 * * * root cd /root/veilkey-selfhosted && docker compose exec -T vaultcenter sqlite3 /data/veilkey.db ".backup /data/backup-$(date +\%Y\%m\%d).db"
```

## 복구 절차

### 1. VaultCenter data 디렉토리에서 복구
```bash
docker compose stop vaultcenter
cp -a data/vaultcenter.bak data/vaultcenter
docker compose start vaultcenter
# POST /api/unlock with KEK password
```

### 2. LXC 스냅샷에서 복구
```bash
pct rollback <vmid> <snapshot-name>
pct start <vmid>
```

### 3. VaultCenter 완전 새로 시작 (최후 수단)
기존 시크릿은 **전부 손실**됨. LocalVault들도 재등록 필요.
```bash
rm -rf data/vaultcenter  # 기존 데이터 삭제
docker compose up -d
docker exec -it veilkey-vaultcenter-1 veilkey-vaultcenter init --root
# 새 KEK password 설정 → 안전한 곳에 저장
# POST /api/admin/setup with owner_password + admin_password
# 새 registration token 발급 → LocalVault들 재등록
```

## KEK vs Admin Password

| 항목 | KEK Password | Admin Password |
|------|-------------|----------------|
| 설정 시점 | `init --root` (최초 1회) | `POST /api/admin/setup` |
| 용도 | DB 암호화 키 파생 + unlock | 웹 UI/API 인증 |
| 변경 가능 | **불가** (DB 재암호화 필요) | 가능 (`/api/admin/change-password`) |
| 분실 시 | **전체 시크릿 영구 손실** | 복구 가능 (KEK로 리셋) |
| 어디에 쓰이나 | `POST /api/unlock` | `POST /api/admin/login` |

## 바이너리 호환성

DB key 파생 함수 (`DeriveDBKeyFromKEK`)가 변경되면 이전 DB를 열 수 없다.

**규칙:**
- 바이너리 업데이트 전 반드시 백업
- data 디렉토리에 현재 바이너리 복사본 보관 (`veilkey-vaultcenter-bin`)
- DB 마이그레이션 없는 key 파생 변경은 **금지**

```bash
# 현재 바이너리 보관
cp $(which veilkey-vaultcenter) data/vaultcenter/veilkey-vaultcenter-bin
```

## 방어 코드 로드맵

### P0 — init 시 기존 DB 보호
- [ ] `init --root` 실행 시 기존 `veilkey.db`가 있으면 거부 (삭제 강제 필요)
- [ ] `--force` 플래그 없으면 기존 데이터 절대 덮어쓰지 않음

### P1 — 자동 백업
- [ ] VaultCenter 시작 시 DB 자동 스냅샷 (`veilkey.db.bak.{timestamp}`)
- [ ] 최근 N개 백업 유지 (기본 5개)

### P2 — 바이너리 호환성 검증
- [ ] DB에 바이너리 버전 + key 파생 버전 저장
- [ ] 버전 불일치 시 unlock 전에 경고

### P3 — 운영자 알림
- [ ] data 디렉토리 삭제/이동 감지 시 Mattermost 알림
- [ ] unlock 실패 5회 이상 시 알림
