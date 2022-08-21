/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */
#include "eunomia/myseccomp.h"

#include "spdlog/spdlog.h"

bool is_not_allow(const std::vector<uint32_t>& syscall_vec, uint32_t id)
{
  for (auto allow : syscall_vec)
  {
    if (id == allow)
      return false;
  }
  return true;
}

static int install_syscall_filter(const std::vector<uint32_t>& syscall_vec)
{
  std::vector<sock_filter> filter_vec = { /* Validate architecture. */
                                          BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4),
                                          BPF_JUMP(BPF_JMP + BPF_JEQ, 0xc000003e, 0, 2),
                                          /* Grab the system call number. */
                                          BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
                                          /* syscalls. */
                                          BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
  };

  size_t syscalls_size = syscall_names_x86_64_size;
  /* add ban rules All syscalls*/
  for (size_t i = 0; i < syscalls_size; i++)
  {
    if (is_not_allow(syscall_vec, (uint32_t)i))
    {
      filter_vec.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ, (uint32_t)i, 0, 1));
      // printf("banned syscall_id : %d\n", i);
      filter_vec.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL));
    }
    else
    {
      spdlog::info("allowed syscall_id : {0:d}", i);
    }
  }

  filter_vec.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));

  sock_filter filter[filter_vec.size()];
  std::copy(filter_vec.begin(), filter_vec.end(), filter);

  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
  {
    perror("prctl(NO_NEW_PRIVS)");
    goto failed;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
  {
    perror("prctl(SECCOMP)");
    goto failed;
  }
  return 0;

failed:
  if (errno == EINVAL)
    fprintf(stderr, "SECCOMP_FILTER is not available. :(n");
  return 1;
}

int get_syscall_id(std::string syscall_name)
{
  for (int i = 0; i < 439; i++)
  {
    if (strcmp(syscall_names_x86_64[i], syscall_name.data()) == 0)
      return i;
  }
  return -1;
}

// Enable Seccomp syscall
// param seccomp_config type is defined by include/eunomia/config.h
int enable_seccomp_white_list(const seccomp_config& config)
{
  spdlog::info("enabled seccomp");
  std::vector<uint32_t> syscall_vec;  // allow_syscall_id list
  for (size_t i = 0; i < config.allow_syscall.size(); i++)
  {
    int id = get_syscall_id(config.allow_syscall[i]);
    if (id == -1)
    {
      spdlog::error(
          "syscall_id error {0} has no corresponding syscall in x86 system "
          "arch",
          config.allow_syscall[i]);
      continue;
    }
    syscall_vec.push_back(id);
  }
  //  printf("ban %d syscalls\n allow %d syscalls\n",config.len,439-config.len);
  if (install_syscall_filter(syscall_vec))
    return 1;

  return 0;
}
