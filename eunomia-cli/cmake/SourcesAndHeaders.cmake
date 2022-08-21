set(sources
    src/libbpf_print.cpp
    src/eunomia_core.cpp
    src/config.cpp
    src/tracker_alone.cpp
    src/http_server.cpp
    src/btf_helpers.c
    src/trace_helpers.c
    src/uprobe_helpers.c
)

set(exe_sources
		src/main.cpp
		${sources}
)

set(headers
    include/eunomia/
)

set(skel_includes
)

set(test_sources
    src/oom_test.cpp
)
