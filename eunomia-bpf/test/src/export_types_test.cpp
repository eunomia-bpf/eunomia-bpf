/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */

#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

#include "eunomia/eunomia-bpf.hpp"

using namespace eunomia;

#define TASK_COMM_LEN 16
#define NAME_MAX      255

struct opensnoop_event
{
  /* user terminology for pid: */
  unsigned long long ts = 1000;
  int pid = 20;
  int uid = 1000;
  int ret = 1;
  int flags = 777;
  char comm[TASK_COMM_LEN] = "hello";
  char fname[NAME_MAX] = "/test/hello/opensnoop";
} opensnoop_event_data;

const char* opensnoop_meta_types =
    "{\"Fields\": [{\"Name\": \"ts\", \"Type\": \"unsigned long long\","
    " \"LLVMType\": \"i64\", \"FieldOffset\": 0}, {\"Name\": \"pid\", \"Type\": \"int\", \"LLVMType\":"
    " \"i32\", \"FieldOffset\": 64}, {\"Name\": \"uid\", \"Type\": \"int\", \"LLVMType\": \"i32\","
    " \"FieldOffset\": 96}, {\"Name\": \"ret\", \"Type\": \"int\", \"LLVMType\": \"i32\", "
    "\"FieldOffset\": 128}, {\"Name\": \"flags\", \"Type\": \"int\", \"LLVMType\": \"i32\","
    " \"FieldOffset\": 160}, {\"Name\": \"comm\", \"Type\": \"char [16]\", \"LLVMType\": \"[16 x i8]\","
    " \"FieldOffset\": 192}, {\"Name\": \"fname\", \"Type\": \"char [255]\", \"LLVMType\":"
    " \"[255 x i8]\", \"FieldOffset\": 320}], \"Struct Name\": \"event\", \"Size\": 2368,"
    " \"DataSize\": 2368, \"Alignment\": 64}";

struct test_case
{
  const char* event;
  const char* json_data;
  const char* plant_text_result;
  const char* json_result;
} test_cases[] = { { reinterpret_cast<const char*>(&opensnoop_event_data),
                     opensnoop_meta_types,
                     "08:38:52 1000 20 1000 1 777 hello /test/hello/opensnoop ",
                     "{\"ts\":1000,\"pid\":20,\"uid\":1000,\"ret\":1,\"flags\":777,\"comm\":\"hello\",\"fname\":\"/test/"
                     "hello/opensnoop\"}" } };

void plant_text_cmp_handler(void* ctx, const char* event)
{
  // skip timestamp
  const char* check_buffer = (const char*)ctx;
  assert(std::strcmp(event + 9, check_buffer + 9) == 0);
}

void json_cmp_handler(void* ctx, const char* event)
{
  const char* check_buffer = (const char*)ctx;
  assert(std::strcmp(event, check_buffer) == 0);
}

int check_event_output(test_case& t_case)
{
  event_exporter exporter;
  ebpf_export_types_meta_data meta;
  int res;

  //  test plant text output
  meta.from_json_str(t_case.json_data);
  exporter.set_export_type(export_format_type::EXPORT_PLANT_TEXT, nullptr);
  res = exporter.check_for_meta_types_and_create_export_format(meta);
  assert(res >= 0);
  std::cout << "check_event_output plant text: " << res << std::endl;
  exporter.handler_export_events(t_case.event);

  //  test json output
  exporter.set_export_type(export_format_type::EXPORT_JSON, nullptr);
  res = exporter.check_for_meta_types_and_create_export_format(meta);
  assert(res >= 0);
  std::cout << "check_event_output json: " << res << std::endl;
  exporter.handler_export_events(t_case.event);

  //  test plant text output to handler
  exporter.set_export_type(export_format_type::EXPORT_PLANT_TEXT, plant_text_cmp_handler, (void*)t_case.plant_text_result);
  res = exporter.check_for_meta_types_and_create_export_format(meta);
  assert(res >= 0);
  std::cout << "check_event handler plant text: " << res << std::endl;
  exporter.handler_export_events(t_case.event);

  // test json output to handler
  exporter.set_export_type(export_format_type::EXPORT_JSON, json_cmp_handler, (void*)t_case.json_result);
  res = exporter.check_for_meta_types_and_create_export_format(meta);
  assert(res >= 0);
  std::cout << "check_event handler json: " << res << std::endl;
  exporter.handler_export_events(t_case.event);

  return 0;
}

int main(int argc, char** argv)
{
  for (auto& test_case : test_cases)
  {
    check_event_output(test_case);
  }
  return 0;
}
