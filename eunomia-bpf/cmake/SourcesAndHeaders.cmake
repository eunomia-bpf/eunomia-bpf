set(sources
    src/eunomia-bpf.cpp
)

set(exe_sources
		src/main.cpp
		${sources}
)

set(headers
    include/eunomia/
)

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )

set(third_party_headers
    ../third_party/includes/
    ../third_party/libbpf/include/uapi
    ../third_party/libbpf/
)

set(test_sources
    src/config_test.cpp
)
