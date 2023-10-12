LD_DEBUG=libs $@ 2> ld_debug_output
library_paths=$(awk '/^.+calling init:/{print $4}' ld_debug_output)
for library_path in $library_paths; do
    target_path="/data/libs${library_path}"
    target_dir=$(dirname "$target_path")
    mkdir -p "$target_dir"
    cp "$library_path" "$target_path"
done
