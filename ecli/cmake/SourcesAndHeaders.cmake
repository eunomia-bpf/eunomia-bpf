set(sources
    src/eunomia_core.cpp
    src/config.cpp
    src/http_server.cpp
    src/eunomia_runner.cpp
    ../eunomia-bpf/eunomia-bpf.cpp
)

set(exe_sources
		src/main.cpp
		${sources}
)

set(headers
)

set(skel_includes
    include/eunomia/
    ../eunomia-bpf/
    ../third_party/includes/
    ../third_party/libbpf/
)

set(test_sources
    src/oom_test.cpp
)
