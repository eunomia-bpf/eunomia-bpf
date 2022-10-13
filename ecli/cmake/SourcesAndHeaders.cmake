set(sources
    src/config.cpp
    src/server.cpp
    src/eunomia_runner.cpp
    src/url_resolver.cpp
    src/cmd_run.cpp
    src/cmd_pull.cpp
    src/cmd_client.cpp
    src/cmd_server.cpp
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
    ../third_party/libbpf/include/uapi/
    ../third_party/libbpf/
)

set(test_sources
    src/example.cpp
)
