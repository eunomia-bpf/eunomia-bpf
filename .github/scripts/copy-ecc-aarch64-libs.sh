LD_DEBUG=libs /data/ecc 2> ld_debug_output
echo "ecc running done"
library_paths=$(awk '/^.+calling init:/{print $4}' ld_debug_output)
echo "raw library paths: $library_paths"
for library_path in $library_paths; do
    target_path="/data/libs${library_path}"
    target_dir=$(dirname "$target_path")
    mkdir -p "$target_dir"
    echo "Copy $library_path"
    cp "$library_path" "$target_path"
done
