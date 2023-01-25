/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#ifndef ECLI_EUNOMIA_RUNNER_H
#define ECLI_EUNOMIA_RUNNER_H

#include <memory>
#include <string>
#include <thread>

#include "config.h"
#include "eunomia/eunomia-bpf.hpp"
#include "ewasm/ewasm.hpp"

class program_runner_base
{
  public:
    program_config_data current_config;
    program_runner_base(program_config_data config)
      : current_config(config)
    {
    }
    virtual ~program_runner_base() = default;
    virtual int load_and_attach_eunomia_skel() = 0;
    virtual std::string get_name() = 0;
    virtual void stop() = 0;
};

/// JSON eBPF program run in kernel
class eunomia_program_runner : public program_runner_base
{
    eunomia::bpf_skeleton program;
    friend class eunomia_runner;

  public:
    eunomia_program_runner(const program_config_data &config)
      : program_runner_base(config){};
    int load_and_attach_eunomia_skel();
    std::string get_name() { return program.get_program_name(); }
    void stop() { program.destroy(); }
    virtual ~eunomia_program_runner() = default;
};

/// @brief  wasm program include kernel and user space
class ewasm_program_runner : public program_runner_base
{
    ewasm_program program;
    friend class eunomia_runner;

  public:
    ewasm_program_runner(const program_config_data &config)
      : program_runner_base(config){};
    int load_and_attach_eunomia_skel();
    std::string get_name()
    { // FIXME: get program name from wasm file
        return "ewasm module";
    }
    void stop()
    {
        // FIXME: stop ewasm program
    }
    virtual ~ewasm_program_runner() = default;
};

class eunomia_runner
{
  private:
    friend class tracker_manager;
    std::unique_ptr<program_runner_base> program_runner;
    bool _is_running = false;

  public:
    std::thread thread;
    /// create a tracker with deafult config
    static std::unique_ptr<eunomia_runner> create_tracker_with_args(
        const program_config_data &config)
    {
        return std::make_unique<eunomia_runner>(config);
    }
    bool is_running() { return _is_running; }
    eunomia_runner(const program_config_data &config)
    {
        if (config.prog_type
            == program_config_data::program_type::JSON_EUNOMIA) {
            program_runner = std::make_unique<eunomia_program_runner>(config);
        }
        else if (config.prog_type
                 == program_config_data::program_type::WASM_MODULE) {
            program_runner = std::make_unique<ewasm_program_runner>(config);
        }
    };
    ~eunomia_runner() { stop_tracker(); }

    /// start process tracker
    int start_tracker()
    {
        _is_running = true;
        int res = program_runner->load_and_attach_eunomia_skel();
        _is_running = false;
        return res;
    }
    const std::string get_name(void) const
    {
        return program_runner->get_name();
    }

    /// stop the tracker thread
    void stop_tracker()
    {
        program_runner->stop();
        if (thread.joinable()) {
            thread.join();
        }
    }
};

#endif