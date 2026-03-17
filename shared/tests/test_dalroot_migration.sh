#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
. tests/lib/testlib.sh

install_script="$PWD/deploy/host/install-veilroot-boundary.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ── extract migration functions from install script ──────────────
# Source only the function definitions and variable defaults, then
# test them in isolation without running the full installer.
eval "$(sed -n '/^migrate_session_tools()/,/^}/p' "$install_script")"
eval "$(sed -n '/^cleanup_legacy_dalroot()/,/^}/p' "$install_script")"
eval "$(sed -n '/^cleanup_legacy_systemd_state()/,/^}/p' "$install_script")"

# set up directory variables used by cleanup functions
bin_dir="$tmp/bin"
systemd_dir="$tmp/systemd"
profile_dir="$tmp/etc/profile.d"
sudoers_dir="$tmp/etc/sudoers.d"
user_name="veilroot"

cat > "$tmp/systemctl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
tmpdir="${TMPDIR:-/tmp}"
printf '%s\n' "$@" >> "$tmpdir/systemctl.log"
SCRIPT
chmod +x "$tmp/systemctl"
systemctl_bin="$tmp/systemctl"

# ═══════════════════════════════════════════════════════════════════
# Test 1: migrate_session_tools converts [dalroot] → [veilroot]
# ═══════════════════════════════════════════════════════════════════
cfg="$tmp/session-tools-1.toml"
cat > "$cfg" <<'TOML'
[dalroot]
unit_prefix = "dalroot"
default_profile = "codex"
TOML

migrate_session_tools "$cfg"

assert_file_contains "$cfg" "[veilroot]"
assert_file_contains "$cfg" 'unit_prefix = "veilroot"'
if grep -q '^\[dalroot\]$' "$cfg"; then
  fail "[dalroot] section still present after migration"
fi

echo "ok: migrate_session_tools converts dalroot to veilroot"

# ═══════════════════════════════════════════════════════════════════
# Test 2: migrate_session_tools is idempotent (already veilroot)
# ═══════════════════════════════════════════════════════════════════
cfg2="$tmp/session-tools-2.toml"
cat > "$cfg2" <<'TOML'
[veilroot]
unit_prefix = "veilroot"
default_profile = "codex"
TOML

cp "$cfg2" "$cfg2.before"
migrate_session_tools "$cfg2"

diff -q "$cfg2" "$cfg2.before" >/dev/null || fail "config changed when already migrated"

echo "ok: migrate_session_tools idempotent on veilroot config"

# ═══════════════════════════════════════════════════════════════════
# Test 3: migrate_session_tools skips when both sections exist
# ═══════════════════════════════════════════════════════════════════
cfg3="$tmp/session-tools-3.toml"
cat > "$cfg3" <<'TOML'
[dalroot]
unit_prefix = "dalroot"

[veilroot]
unit_prefix = "veilroot"
TOML

cp "$cfg3" "$cfg3.before"
migrate_session_tools "$cfg3"

# migration should be skipped — both sections remain as-is
diff -q "$cfg3" "$cfg3.before" >/dev/null || fail "config changed when both sections present"
grep -q '^\[dalroot\]$' "$cfg3" || fail "dalroot section was unexpectedly removed"
assert_file_contains "$cfg3" "[veilroot]"

echo "ok: migrate_session_tools skips when both sections present"

# ═══════════════════════════════════════════════════════════════════
# Test 4: migrate_session_tools handles missing file gracefully
# ═══════════════════════════════════════════════════════════════════
migrate_session_tools "/nonexistent/path/session-tools.toml"
migrate_session_tools ""

echo "ok: migrate_session_tools handles missing/empty path"

# ═══════════════════════════════════════════════════════════════════
# Test 5: cleanup_legacy_dalroot removes all dalroot artifacts
# ═══════════════════════════════════════════════════════════════════
mkdir -p "$bin_dir" "$systemd_dir" "$profile_dir" "$sudoers_dir"
touch "$bin_dir/veilkey-dalroot-session"
touch "$bin_dir/veilkey-dalroot-observe"
touch "$bin_dir/veilkey-dalroot-egress-guard"
touch "$bin_dir/verify-dalroot-session"
touch "$systemd_dir/veilkey-dalroot-observe@.service"
touch "$systemd_dir/veilkey-dalroot-egress-guard@.service"
touch "$profile_dir/dalroot-workspace.sh"
touch "$profile_dir/dalroot-veilkey-proxy.sh"
touch "$sudoers_dir/dalroot"

# also place a non-dalroot file to ensure it survives
touch "$bin_dir/veilkey-veilroot-session"

cleanup_legacy_dalroot

test ! -f "$bin_dir/veilkey-dalroot-session" || fail "veilkey-dalroot-session not removed"
test ! -f "$bin_dir/veilkey-dalroot-observe" || fail "veilkey-dalroot-observe not removed"
test ! -f "$bin_dir/veilkey-dalroot-egress-guard" || fail "veilkey-dalroot-egress-guard not removed"
test ! -f "$bin_dir/verify-dalroot-session" || fail "verify-dalroot-session not removed"
test ! -f "$systemd_dir/veilkey-dalroot-observe@.service" || fail "dalroot observe service not removed"
test ! -f "$systemd_dir/veilkey-dalroot-egress-guard@.service" || fail "dalroot egress guard service not removed"
test ! -f "$profile_dir/dalroot-workspace.sh" || fail "dalroot-workspace.sh not removed"
test ! -f "$profile_dir/dalroot-veilkey-proxy.sh" || fail "dalroot-veilkey-proxy.sh not removed"
test ! -f "$sudoers_dir/dalroot" || fail "dalroot sudoers not removed"

# non-dalroot file must survive
test -f "$bin_dir/veilkey-veilroot-session" || fail "non-dalroot file incorrectly removed"

echo "ok: cleanup_legacy_dalroot removes all dalroot artifacts"

# ═══════════════════════════════════════════════════════════════════
# Test 6: cleanup_legacy_dalroot is safe when no dalroot files exist
# ═══════════════════════════════════════════════════════════════════
rm -rf "$bin_dir" "$systemd_dir" "$profile_dir" "$sudoers_dir"
mkdir -p "$bin_dir" "$systemd_dir" "$profile_dir" "$sudoers_dir"

cleanup_legacy_dalroot

echo "ok: cleanup_legacy_dalroot safe with no dalroot files"

# ═══════════════════════════════════════════════════════════════════
# Test 7: cleanup_legacy_systemd_state issues stop/disable/reset
# ═══════════════════════════════════════════════════════════════════
: > "$tmp/systemctl.log"

TMPDIR="$tmp" cleanup_legacy_systemd_state

# dalroot services for all profiles
for profile in codex claude opencode default; do
  grep -q "veilkey-dalroot-observe@${profile}.service" "$tmp/systemctl.log" \
    || fail "systemctl did not touch dalroot-observe@${profile}"
  grep -q "veilkey-dalroot-egress-guard@${profile}.service" "$tmp/systemctl.log" \
    || fail "systemctl did not touch dalroot-egress-guard@${profile}"
done

# verify stop/disable/reset-failed commands were issued
grep -q '^stop$' "$tmp/systemctl.log" || fail "systemctl stop not called"
grep -q '^disable$' "$tmp/systemctl.log" || fail "systemctl disable not called"
grep -q '^reset-failed$' "$tmp/systemctl.log" || fail "systemctl reset-failed not called"

echo "ok: cleanup_legacy_systemd_state handles dalroot units"

echo ""
echo "all dalroot migration tests passed"
