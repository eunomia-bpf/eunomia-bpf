/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

#include "eunomia/eunomia-bpf.hpp"

int main(int argc, char **argv)
{
  std::ifstream fs("../../test/asserts/bootstrap.json");

  if (!fs.is_open())
  {
    std::cerr << "Failed to open json file" << std::endl;
    return -1;
  }
  std::string json_str((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
  fs.close();
  eunomia::bpf_skeleton program;
  assert(program.open_from_json_config(json_str) == 0);
  return 0;
}
