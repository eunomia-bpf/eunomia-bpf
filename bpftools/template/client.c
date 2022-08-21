// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

#include ".output/client.skel.h"
#include "cJSON.h"
#include "base64_encode.h"

const char* config_file_name = "config.json";

cJSON * parse_json_file(void)
{
  FILE *f;
  long len;
  char *data;

  f = fopen(config_file_name, "rb");
  if (!f) {
    fprintf(stderr, "Failed to open config file %s\n", config_file_name);
    exit(1);
  }
  fseek(f, 0, SEEK_END);
  len = ftell(f);
  fseek(f, 0, SEEK_SET);
  data = (char *)malloc(len + 1);
  fread(data, 1, len, f);
  fclose(f);
  cJSON *result = cJSON_Parse(data);
  free(data);
  return result;
}

int main(int argc, char **argv)
{
  struct client_bpf obj;
  char *string;
  // TODO: this is unnecessary, use bpftools instead

  if (client_bpf__create_skeleton(&obj))
  {
    return 1;
  }
  cJSON *result = parse_json_file();
  size_t out_len;
  cJSON *map = NULL;
  cJSON *maps = NULL;
  cJSON *prog = NULL;
  cJSON *progs = NULL;
  cJSON *data = NULL;
  cJSON *data_sz = NULL;
  unsigned char *base64_buffer = NULL;

  data_sz = cJSON_CreateNumber(obj.skeleton->data_sz);
  if (data_sz == NULL)
  {
    goto end;
  }
  cJSON_AddItemToObject(result, "data_sz", data_sz);

  base64_buffer = base64_encode(obj.skeleton->data, obj.skeleton->data_sz, &out_len);
  data = cJSON_CreateString((const char*)base64_buffer);
  if (data == NULL)
  {
    goto end;
  }
  cJSON_AddItemToObject(result, "data", data);

  maps = cJSON_CreateArray();
  for (size_t i = 0; i < obj.skeleton->map_cnt; ++i)
  {
    map = cJSON_CreateString(obj.skeleton->maps[i].name);
    if (map == NULL)
    {
      goto end;
    }
    cJSON_AddItemToArray(maps, map);
  }
  cJSON_AddItemToObject(result, "maps", maps);

  progs = cJSON_CreateArray();
  for (size_t i = 0; i < obj.skeleton->prog_cnt; ++i)
  {
    prog = cJSON_CreateString(obj.skeleton->progs[i].name);
    if (prog == NULL)
    {
      goto end;
    }
    cJSON_AddItemToArray(progs, prog);
  }
  cJSON_AddItemToObject(result, "progs", progs);
  string = cJSON_Print(result);
  if (string == NULL)
  {
    fprintf(stderr, "Failed to print monitor.\n");
  }
  printf("%s", string);

end:
  cJSON_Delete(result);
  if (base64_buffer)
    free(base64_buffer);
  return 0;
}
