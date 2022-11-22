set(sources
    src/eunomia_bpf.cpp
    src/export_events.cpp
    src/eunomia_meta.cpp
    src/section_data.cpp
    src/arg_parser.cpp
    src/trace_helpers.c
    src/uprobe_helpers.c
    src/map_helpers.c
    src/btf_helpers.c
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
    ../third_party/bpftool/libbpf/include/uapi
    ../third_party/bpftool/libbpf/
    include/helpers/
)

set(test_sources
    src/config_test.cpp
    src/export_types_test.cpp
    src/test_c_api.c
)
