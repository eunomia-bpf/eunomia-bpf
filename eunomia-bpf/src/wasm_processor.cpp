#ifdef ENABLE_EUNOMIA_WASM
#include <fstream>
#include <iostream>
#include <sstream>
#include <wasmtime.hh>

#include "eunomia/processor.hpp"
#include "json.hpp"

using namespace wasmtime;
using namespace eunomia;
using nlohmann::json;

std::string eunomia_wasm_processor::run_wasm_for_load_json(const std::string& json_str)
{
  Engine engine;
  Store store(engine);
  if (wasm_code.empty())
  {
    return json_str;
  }
  try
  {
    std::string processed_json;
    auto module = Module::compile(engine, wasm_code).unwrap();
    auto instance = Instance::create(store, module, {}).unwrap();
    auto process_func = std::get<Func>(*instance.get(store, "load_json"));
    auto memory = std::get<Memory>(*instance.get(store, "memory"));
    memory.data(store);
    auto result = process_func.call(store, { 0 });
  }
  catch (const std::exception& e)
  {
    std::cerr << e.what() << std::endl;
  }
  return json_str;
}

eunomia_ebpf_meta_data eunomia_wasm_processor::create_meta_from_json(const std::string& json_str)
{
  eunomia_ebpf_meta_data meta_data;
  try
  {
    auto json_obj = json::parse(json_str);
    this->runtime_args = json_obj["runtime_args"].dump();
    this->wasm_code = json_obj["wasm"];
  }
  catch (...)
  {
  }
  std::string processed_json = run_wasm_for_load_json(json_str);
  meta_data.from_json_str(json_str);
  return meta_data;
}

#endif
