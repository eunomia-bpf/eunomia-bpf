#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

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

int test_create_and_stop() {
  const char* data = read_file_data("../../test/asserts/minimal.json");
  struct eunomia_bpf* ctx = create_ebpf_program_from_json(data);
  assert(ctx);
  stop_and_clean_ebpf_program(ctx);
  free((void*)data);
}

int test_create_and_run() {
  const char* data = read_file_data("../../test/asserts/minimal.json");
  struct eunomia_bpf* ctx = create_ebpf_program_from_json(data);
  assert(ctx);
  int res = run_ebpf_program(ctx);
  assert(res == 0);
  stop_and_clean_ebpf_program(ctx);
  free((void*)data);
}

int test_create_and_run_multi() {
  const char* data = read_file_data("../../test/asserts/minimal.json");
  struct eunomia_bpf* ctx1 = create_ebpf_program_from_json(data);
  assert(ctx1);
  int res = run_ebpf_program(ctx1);
  assert(res == 0);
  // run again, should fail
  res = run_ebpf_program(ctx1);
  assert(res == 1);

  struct eunomia_bpf* ctx2 = create_ebpf_program_from_json(data);
  res = run_ebpf_program(ctx2);
  assert(res == 0);
  
  stop_and_clean_ebpf_program(ctx1);
  stop_and_clean_ebpf_program(ctx2);
  free((void*)data);
}

int main(int argc, char** argv)
{
  return 0;
}
