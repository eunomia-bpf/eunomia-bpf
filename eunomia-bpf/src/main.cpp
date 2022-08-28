#include <eunomia/eunomia-bpf.hpp>
#include <fstream>
#include <iostream>

using namespace eunomia;

/// a dummy loader for test
int main(int argc, char *argv[])
{
  std::string json_str;
  while (std::getline(std::cin, json_str))
  {
  }
  std::cout << json_str << std::endl;
  eunomia_ebpf_program ebpf_program{ json_str };
  if (ebpf_program.run())
  {
    std::cerr << "Failed to run ebpf program" << std::endl;
    return -1;
  }
  if (ebpf_program.wait_and_export())
  {
    std::cerr << "Failed to wait and print rb" << std::endl;
    return -1;
  }
  ebpf_program.stop_and_clean();
  return 0;
}