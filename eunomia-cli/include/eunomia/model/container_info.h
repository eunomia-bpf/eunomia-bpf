#ifndef CONTAINER_INFO_H
#define CONTAINER_INFO_H

#include <string>

/// statues of container
enum class container_status
{
  RUNNING,
  EXITED,
  INVALID,
};

/// container info from str
static container_status container_status_from_str(const std::string &s)
{
  if (s == "running")
  {
    return container_status::RUNNING;
  }
  else if (s == "exited")
  {
    return container_status::EXITED;
  }
  else
  {
    return container_status::INVALID;
  }
}

///  container info
struct container_info
{
  /// container id
  std::string id;
  /// container name
  std::string name;
  /// container status
  container_status status;
};

#endif