#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

make_fixture() {
	local workspace
	workspace="$(mktemp -d)"

	mkdir -p "$workspace/ecli" "$workspace/compiler" "$workspace/eunomia/bin"

	cat >"$workspace/ecli/Makefile" <<'EOF'
install:
	mkdir -p "$(EUNOMIA_HOME)/bin"
	printf '%s\n' 'new-release' > "$(EUNOMIA_HOME)/release-id"
	printf '%s\n' 'new-ecli' > "$(EUNOMIA_HOME)/bin/ecli"
EOF

	cat >"$workspace/compiler/Makefile" <<'EOF'
install:
	mkdir -p "$(EUNOMIA_HOME)/bin"
	printf '%s\n' 'new-ecc' > "$(EUNOMIA_HOME)/bin/ecc"
EOF

	printf '%s\n' 'old-release' >"$workspace/eunomia/release-id"
	printf '%s\n' 'legacy-runtime' >"$workspace/eunomia/legacy.txt"
	printf '%s\n' 'old-ecli' >"$workspace/eunomia/bin/ecli"
	tar -czf "$workspace/eunomia.tar.gz" -C "$workspace" eunomia

	printf '%s\n' "$workspace"
}

assert_file_content() {
	local path=$1
	local expected=$2

	if ! grep -qxF "$expected" "$path"; then
		printf 'expected %s to contain %s\n' "$path" "$expected" >&2
		return 1
	fi
}

assert_no_temp_roots() {
	local workspace=$1

	if find "$workspace" -maxdepth 1 \( -name '.eunomia.release.*' -o -name '.eunomia.previous.*' \) | grep -q .; then
		printf 'expected no leftover temporary release artifacts in %s\n' "$workspace" >&2
		return 1
	fi
}

assert_tarball_matches_runtime() {
	local workspace=$1
	local extract_root

	extract_root="$(mktemp -d)"
	tar -xzf "$workspace/eunomia.tar.gz" -C "$extract_root"
	if ! diff -qr "$workspace/eunomia" "$extract_root/eunomia" >/dev/null; then
		diff -qr "$workspace/eunomia" "$extract_root/eunomia" >&2 || true
		rm -rf "$extract_root"
		printf 'expected %s/eunomia.tar.gz to match %s/eunomia\n' "$workspace" "$workspace" >&2
		return 1
	fi
	rm -rf "$extract_root"
}

test_release_success() {
	local workspace
	workspace="$(make_fixture)"
	trap 'rm -rf "$workspace"' RETURN

	make -s -C "$workspace" -f "$repo_root/Makefile" release

	assert_file_content "$workspace/eunomia/release-id" "new-release"
	assert_file_content "$workspace/eunomia/bin/ecli" "new-ecli"
	assert_file_content "$workspace/eunomia/bin/ecc" "new-ecc"
	test -f "$workspace/eunomia.tar.gz"
	test ! -e "$workspace/eunomia/legacy.txt"
	assert_tarball_matches_runtime "$workspace"
	assert_no_temp_roots "$workspace"
}

make_failing_rm() {
	local wrapper_dir=$1

	mkdir -p "$wrapper_dir"
	cat >"$wrapper_dir/rm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

marker=${RM_FAIL_MARKER:?}

for arg in "$@"; do
	case "$arg" in
		*/.eunomia.previous.*)
			if [ ! -e "$marker" ] && [ -d "$arg" ]; then
				touch "$marker"
				first_entry="$(find "$arg" -mindepth 1 -maxdepth 1 | head -n 1 || true)"
				if [ -n "$first_entry" ]; then
					/bin/rm -rf "$first_entry"
				fi
				printf '%s\n' "simulated partial backup deletion for $arg" >&2
				exit 1
			fi
			;;
	esac
done

exec /bin/rm "$@"
EOF
	chmod +x "$wrapper_dir/rm"
}

make_failing_mv() {
	local wrapper_dir=$1

	mkdir -p "$wrapper_dir"
	cat >"$wrapper_dir/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

marker=${MV_FAIL_MARKER:?}
mode=${MV_FAIL_MODE:-runtime-promotion}
args=("$@")

if [ "${#args[@]}" -ge 2 ]; then
	src="${args[$((${#args[@]} - 2))]}"
	dest="${args[$((${#args[@]} - 1))]}"

	if [ ! -e "$marker" ]; then
		if [ "$mode" = "runtime-promotion" ] && [[ "$src" == */.eunomia.release.*/eunomia ]] && [ "$dest" = "eunomia" ]; then
			touch "$marker"
			printf '%s\n' "simulated runtime promotion failure for $src -> $dest" >&2
			exit 1
		fi

		if [ "$mode" = "archive-backup" ] && [ "$src" = "eunomia.tar.gz" ] && [[ "$dest" == ./.eunomia.previous.tar.gz.* ]]; then
			touch "$marker"
			printf '%s\n' "simulated archive backup failure for $src -> $dest" >&2
			exit 1
		fi
	fi
fi

exec /bin/mv "$@"
EOF
	chmod +x "$wrapper_dir/mv"
}

test_release_restores_old_surface_when_runtime_swap_fails() {
	local workspace status
	workspace="$(make_fixture)"
	trap 'rm -rf "$workspace"' RETURN

	make_failing_mv "$workspace/bin"

	if PATH="$workspace/bin:$PATH" MV_FAIL_MARKER="$workspace/mv.failed" MV_FAIL_MODE=runtime-promotion \
		make -s -C "$workspace" -f "$repo_root/Makefile" release; then
		status=0
	else
		status=$?
	fi

	if [ "$status" -eq 0 ]; then
		printf 'expected release to fail when runtime promotion fails\n' >&2
		return 1
	fi

	assert_file_content "$workspace/eunomia/release-id" "old-release"
	assert_file_content "$workspace/eunomia/bin/ecli" "old-ecli"
	test -f "$workspace/eunomia/legacy.txt"
	test ! -e "$workspace/eunomia/bin/ecc"
	test -f "$workspace/eunomia.tar.gz"
	assert_tarball_matches_runtime "$workspace"
	test -f "$workspace/mv.failed"
	assert_no_temp_roots "$workspace"
}

test_release_preserves_new_runtime_when_backup_cleanup_fails() {
	local workspace status backup_root
	workspace="$(make_fixture)"
	trap 'rm -rf "$workspace"' RETURN

	make_failing_rm "$workspace/bin"

	if PATH="$workspace/bin:$PATH" RM_FAIL_MARKER="$workspace/rm.failed" \
		make -s -C "$workspace" -f "$repo_root/Makefile" release; then
		status=0
	else
		status=$?
	fi

	if [ "$status" -eq 0 ]; then
		printf 'expected release to fail when backup cleanup fails\n' >&2
		return 1
	fi

	assert_file_content "$workspace/eunomia/release-id" "new-release"
	assert_file_content "$workspace/eunomia/bin/ecli" "new-ecli"
	assert_file_content "$workspace/eunomia/bin/ecc" "new-ecc"
	test -f "$workspace/eunomia.tar.gz"
	test ! -e "$workspace/eunomia/legacy.txt"
	assert_tarball_matches_runtime "$workspace"
	test -f "$workspace/rm.failed"

	backup_root="$(find "$workspace" -maxdepth 1 -type d -name '.eunomia.previous.*' -print -quit)"
	if [ -z "$backup_root" ]; then
		printf 'expected the partially deleted backup tree to remain for inspection\n' >&2
		return 1
	fi

	if find "$workspace" -maxdepth 1 \( -name '.eunomia.release.*' -o -name '.eunomia.previous.tar.gz.*' \) | grep -q .; then
		printf 'expected release staging roots and archive backups to be cleaned up after failure\n' >&2
		return 1
	fi
}

test_release_restores_old_surfaces_when_archive_backup_fails() {
	local workspace status
	workspace="$(make_fixture)"
	trap 'rm -rf "$workspace"' RETURN

	make_failing_mv "$workspace/bin"

	if PATH="$workspace/bin:$PATH" MV_FAIL_MARKER="$workspace/mv-archive.failed" MV_FAIL_MODE=archive-backup \
		make -s -C "$workspace" -f "$repo_root/Makefile" release; then
		status=0
	else
		status=$?
	fi

	if [ "$status" -eq 0 ]; then
		printf 'expected release to fail when archive backup fails\n' >&2
		return 1
	fi

	assert_file_content "$workspace/eunomia/release-id" "old-release"
	assert_file_content "$workspace/eunomia/bin/ecli" "old-ecli"
	test -f "$workspace/eunomia/legacy.txt"
	test ! -e "$workspace/eunomia/bin/ecc"
	test -f "$workspace/eunomia.tar.gz"
	assert_tarball_matches_runtime "$workspace"
	test -f "$workspace/mv-archive.failed"
	assert_no_temp_roots "$workspace"
}

test_release_success
test_release_restores_old_surface_when_runtime_swap_fails
test_release_preserves_new_runtime_when_backup_cleanup_fails
test_release_restores_old_surfaces_when_archive_backup_fails
