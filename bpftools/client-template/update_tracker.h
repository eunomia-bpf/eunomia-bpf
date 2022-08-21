
#ifndef UPDATE_TRACKER_H
#define UPDATE_TRACKER_H

extern "C"
{
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

#include "update.h"
}
#include "../../include/hot_update_templates/single_prog_update_skel.h"

static const char argp_program_doc[] =
    "BPF update demo application.\n"
    "\n"
    "It traces process start and exits and shows associated \n"
    "information (filename, process duration, PID and PPID, etc).\n"
    "\n"
    "USAGE: ./update [-d <min-duration-ms>] [-v]\n";

static volatile bool exiting = false;

static void sig_handler(int sig)
{
  exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
  const struct event *e = (const struct event *)data;
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (e->exit_event)
  {
    printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "", e->comm, e->pid, e->ppid, e->exit_code);
    if (e->duration_ns)
      printf(" (%llums)", e->duration_ns / 1000000);
    printf("\n");
  }
  else
  {
    printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "", e->comm, e->pid, e->ppid, e->filename);
  }
  return 0;
}

static int start_updatable(int argc, char **argv)
{
  struct ring_buffer *rb = NULL;
  struct single_prog_update_bpf *skel;
  int err;

  if (argc != 2)
  {
    printf("invalid arg count %d\n", argc);
    return 1;
  }
  std::string json_str = argv[1];

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  struct ebpf_update_meta_data ebpf_data;
  ebpf_data.from_json_str(json_str);
  skel = single_prog_eunomia_bpf_decode_open(ebpf_data);
  if (!skel)
  {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = eunomia_bpf_load(skel);
  if (err)
  {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = eunomia_bpf_attach(skel);
  if (err)
  {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb)
  {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Process events */
  printf("%-8s %-16s %-7s %-7s %s\n", "TIME", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
  while (!exiting)
  {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR)
    {
      err = 0;
      break;
    }
    if (err < 0)
    {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  /* Clean up */
  ring_buffer__free(rb);
  eunomia_bpf_destroy(skel);

  return err < 0 ? -err : 0;
}

#endif
