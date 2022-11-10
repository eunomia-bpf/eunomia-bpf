/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

#include "eunomia/eunomia-meta.hpp"

using namespace eunomia;

int
main(int argc, char **argv)
{
    std::ifstream condig_file("../../test/asserts/client.skel.json");

    if (!condig_file.is_open()) {
        std::cerr << "Failed to open json file" << std::endl;
        return -1;
    }
    std::string json_str((std::istreambuf_iterator<char>(condig_file)),
                         std::istreambuf_iterator<char>());
    eunomia_object_meta meta;
    meta.from_json_str(json_str);
    return 0;
}
