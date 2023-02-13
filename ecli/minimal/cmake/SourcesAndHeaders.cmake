set(sources
    src/config.cpp
    src/eunomia_runner.cpp
    src/url_resolver.cpp
)

set(exe_sources
		src/main.cpp
		${sources}
)

set(headers
)

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )

set(third_party_headers
    ../third_party/includes/
    ../third_party/bpftool/libbpf/include/uapi/
    ../third_party/bpftool/libbpf/
)

set(test_sources
    src/example.cpp
)
