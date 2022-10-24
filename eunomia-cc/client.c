// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

#include "libs/cJSON.h"
#include "libs/create_skel_json.h"

int main(int argc, char **argv)
{
  char *string;
  cJSON * config_json = cJSON_CreateObject();
  config_json = create_skel_json(config_json);
  if (!config_json)
  {
    fprintf(stderr, "Failed to create skel json\n");
    exit(1);
  }
  string = cJSON_Print(config_json);
  if (string == NULL)
  {
    fprintf(stderr, "Failed to print monitor.\n");
  }
  printf("%s", string);

  cJSON_Delete(config_json);
  return 0;
}
