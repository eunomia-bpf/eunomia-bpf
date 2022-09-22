#ifndef EUNOMIA_UTILS
#define EUNOMIA_UTILS

#include <string>

static bool str_ends_with(const std::string &str, const std::string &suffix)
{
    std::string::size_type totalSize = str.size();
    std::string::size_type suffixSize = suffix.size();

    if(totalSize < suffixSize) {
        return false;
    }
    return str.compare(totalSize - suffixSize, suffixSize, suffix) == 0;
}

#endif