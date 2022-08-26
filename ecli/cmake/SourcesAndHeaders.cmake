set(sources
    src/ecli_core.cpp
    src/config.cpp
    src/http_server.cpp
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
    ../third_party/libbpf/include/uapi
    ../third_party/libbpf/
)

set(skel_includes
)

set(test_sources
    src/oom_test.cpp
    src/get_file_test.cpp
)
