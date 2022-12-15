#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fstream>
#include <catch2/catch_test_macros.hpp>

#include "eunomia/eunomia-bpf.hpp"

using namespace eunomia;
std::string
read_file_data(const char *path)
{
    std::ifstream json_file(path);
    std::string json_str((std::istreambuf_iterator<char>(json_file)),
                         std::istreambuf_iterator<char>());
    return json_str;
}

int
test_create_and_stop()
{
    bpf_skeleton ebpf_program;
    auto json_package = read_file_data("../../test/asserts/bootstrap.json");
    REQUIRE(ebpf_program.open_from_json_config(json_package) == 0);
    ebpf_program.destroy();
    return 0;
}

int
test_create_and_run()
{
    bpf_skeleton ebpf_program;
    auto json_package = read_file_data("../../test/asserts/bootstrap.json");
    REQUIRE(ebpf_program.open_from_json_config(json_package) == 0);
    REQUIRE(ebpf_program.load_and_attach() == 0);
    ebpf_program.destroy();
    return 0;
}

int
test_create_and_run_multi()
{
    bpf_skeleton ebpf_program;
    auto json_package = read_file_data("../../test/asserts/bootstrap.json");
    REQUIRE(ebpf_program.open_from_json_config(json_package) == 0);
    REQUIRE(ebpf_program.load_and_attach() == 0);
    bpf_skeleton ebpf_program2;
    REQUIRE(ebpf_program2.open_from_json_config(json_package) == 0);
    REQUIRE(ebpf_program2.load_and_attach() == 0);
    ebpf_program.destroy();
    ebpf_program2.destroy();
    return 0;
}

TEST_CASE("creat and stop", "[creat]")
{
    REQUIRE(test_create_and_stop() == 0);
}

TEST_CASE("creat and run", "[creat]")
{
    REQUIRE(test_create_and_run() == 0);
}

TEST_CASE("creat and run multi", "[creat]")
{
    REQUIRE(test_create_and_run_multi() == 0);
}
