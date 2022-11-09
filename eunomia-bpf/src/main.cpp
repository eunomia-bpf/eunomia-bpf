#include <eunomia/eunomia-bpf.hpp>
#include <fstream>
#include <iostream>

using namespace eunomia;

/// a dummy loader for test
int main(int argc, char *argv[])
{
  std::string json_str;
  if (argc == 2)
  {
    std::ifstream json_file(argv[1]);
    if (json_file.is_open())
    {
      std::string line;
      while (std::getline(json_file, line))
      {
        json_str += line;
      }
      json_file.close();
    }
  }
  else
  {
    json_str = std::string((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
  }
  std::cout << json_str << std::endl;
  bpf_skeleton ebpf_program{ json_str, {} };
  if (ebpf_program.load_and_attach())
  {
    std::cerr << "Failed to run ebpf program" << std::endl;
    return -1;
  }
  if (ebpf_program.wait_and_poll())
  {
    std::cerr << "Failed to wait and print rb" << std::endl;
    return -1;
  }
  ebpf_program.destory();
  return 0;
}