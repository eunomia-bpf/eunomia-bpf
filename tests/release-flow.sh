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
		printf 'expected no leftover temporary release roots in %s\n' "$workspace" >&2
		return 1
	fi
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
	test -f "$workspace/rm.failed"

	backup_root="$(find "$workspace" -maxdepth 1 -type d -name '.eunomia.previous.*' -print -quit)"
	if [ -z "$backup_root" ]; then
		printf 'expected the partially deleted backup tree to remain for inspection\n' >&2
		return 1
	fi

	if find "$workspace" -maxdepth 1 -type d -name '.eunomia.release.*' | grep -q .; then
		printf 'expected release staging roots to be cleaned up after failure\n' >&2
		return 1
	fi
}

test_release_success
test_release_preserves_new_runtime_when_backup_cleanup_fails
