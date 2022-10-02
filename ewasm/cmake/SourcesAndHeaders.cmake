set(sources
    src/ewasm.c
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
    src/example_test.cpp
)
