if(${PROJECT_NAME}_ENABLE_DOXYGEN)
    set(DOXYGEN_PROJECT_NAME "Eunomia")
    set(DOXYGEN_PROJECT_BRIEF "A lightweight eBPF-based CloudNative Monitor tool for Container Security and Observability")

    set(DOXYGEN_CALLER_GRAPH YES)
    set(DOXYGEN_CALL_GRAPH YES)
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_UML_LOOK YES)
    set(DOXYGEN_CLASS_DIAGRAMS YES)
    set(DOXYGEN_CLASS_GRAPH YES)
    set(DOXYGEN_COLLABORATION_GRAPH YES)
    set(DOXYGEN_TEMPLATE_RELATIONS YES)

    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE README.md)
    set(DOXYGEN_GENERATE_TREEVIEW YES)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs)
    set(DOXYGEN_EXCLUDE_PATTERNS */doc/develop_doc/* */vmlinux/* */third_party/* */libbpf/* */libbpf/* */bpftools/* */cmake/* */.github/* */.vscode/* */build/* */include/clipp.h */include/httplib.h */include/json.hpp */include/toml.hpp */include/spdlog/*)

    find_package(Doxygen REQUIRED dot)
    doxygen_add_docs(doxygen-docs ${PROJECT_SOURCE_DIR})

    verbose_message("Doxygen has been setup and documentation is now available.")
endif()
