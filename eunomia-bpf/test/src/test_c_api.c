#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "eunomia/eunomia-bpf.h"

const char* read_file_data(const char* path)
{
  int res = 0;
  FILE* fp = fopen(path, "r");
  if (!fp)
  {
    return NULL;
  }
  res = fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  res = fseek(fp, 0, SEEK_SET);
  char* data = malloc(size + 1);
  if (!data)
  {
    fclose(fp);
    return NULL;
  }
  res = fread(data, size, 1, fp);
  data[size] = '\0';
  res = fclose(fp);
  return data;
}

int main(int argc, char** argv)
{
  const char* data = read_file_data("../../test/asserts/minimal.json");
  struct eunomia_bpf* ctx = create_ebpf_program_from_json(data);
  if (!ctx)
  {
    printf("Failed to create eunomia bpf program\n");
    return 1;
  }
  // failed if not in root
  // FIXME: possible double free if not in root?
  // int res = run_ebpf_program(ctx);
  // res = sleep(1);
  stop_and_clean_ebpf_program(ctx);
  free((void*)data);
  return 0;
}
