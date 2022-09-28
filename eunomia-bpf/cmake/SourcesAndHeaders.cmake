set(sources
    src/eunomia_bpf.cpp
    src/export_events.cpp
    src/eunomia_meta.cpp
    src/processor.cpp
    src/wasm_processor.cpp
)

set(exe_sources
		src/main.cpp
		${sources}
)

set(headers
    include/
)

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )

set(third_party_headers
    ../third_party/includes/
    ../third_party/libbpf/include/uapi
    ../third_party/libbpf/
    ../third_party/wasmtime/include
)

set(test_sources
    src/config_test.cpp
    src/export_types_test.cpp
    src/test_c_api.c
    src/wasm_test.cpp
)
