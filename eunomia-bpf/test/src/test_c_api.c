#include <stdio.h>

#include "eunomia/eunomia-bpf.h"

int main(int argc, char** argv)
{
  if (argc != 2)
  {
    printf("Usage: %s <bpf-json>\n", argv[0]);
    return 1;
  }
  struct eunomia_bpf* ctx = create_ebpf_program_from_json(argv[1]);
  if (!ctx)
  {
    printf("Failed to create eunomia bpf program\n");
    return 1;
  }
  int res = run_ebpf_program(ctx);
  if (res < 0)
  {
    printf("Failed to run eunomia bpf program\n");
    return 1;
  }
  res = wait_and_export_ebpf_program(ctx);
  if (res < 0)
  {
    printf("Failed to wait and export eunomia bpf program\n");
    return 1;
  }
  stop_and_clean_ebpf_program(ctx);
  return 0;
}
