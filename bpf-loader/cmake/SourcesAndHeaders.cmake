set(sources
    src/eunomia_bpf.cpp
    src/export_events.cpp
    src/eunomia_meta.cpp
    src/section_data.cpp
    src/attach.cpp
    src/arg_parser.cpp
    src/trace_helpers.c
    src/uprobe_helpers.c
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
    src/auto_polling_test.cpp
    src/c_skel_test.c
    src/cpp_skel_test.cpp
    src/arg_parser_test.cpp
    src/helpers_test.cpp
)
