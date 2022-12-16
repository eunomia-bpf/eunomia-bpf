/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "helpers/map_helpers.h"
#include "helpers/trace_helpers.h"
}

using json = nlohmann::json;
namespace eunomia {

/// if the field exists, get it. if not, use the default value
#define get_from_json_or_default(json_object, name)                  \
    do {                                                             \
        json res;                                                    \
        try {                                                        \
            res = json_object.at(#name);                             \
        } catch (...) {                                              \
            std::cerr << #name << " is not set, default is " << name \
                      << std::endl;                                  \
            break;                                                   \
        }                                                            \
        res.get_to(name);                                            \
    } while (0);

int
bpf_skeleton::attach_tc_prog(std::size_t id)
{
    int ifindex = 1;
    __u32 handle = 1;
    __u32 priority = 1;
    enum bpf_tc_attach_point attach_point_value = BPF_TC_INGRESS;

    json j = json::parse(meta_data.bpf_skel.progs[id].__raw_json_data);
    json tchook;
    get_from_json_or_default(j, tchook);
    if (!tchook.is_null()) {
        get_from_json_or_default(tchook, ifindex);
        std::string attach_point = "BPF_TC_INGRESS";
        std::map<std::string, enum bpf_tc_attach_point> attach_point_map = {
            { "BPF_TC_INGRESS", BPF_TC_INGRESS },
            { "BPF_TC_EGRESS", BPF_TC_EGRESS },
            { "BPF_TC_CUSTOM", BPF_TC_CUSTOM },
        };
        get_from_json_or_default(tchook, attach_point);
        if (attach_point_map.find(attach_point) != attach_point_map.end()) {
            attach_point_value = attach_point_map[attach_point];
        }
        else {
            std::cerr << "error: attach_point " << attach_point
                      << " is not supported" << std::endl;
            return -1;
        }
    }
    json tcopts;
    get_from_json_or_default(j, tcopts);
    if (!tcopts.is_null()) {
        get_from_json_or_default(tcopts, handle);
        get_from_json_or_default(tcopts, priority);
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
                        .attach_point = attach_point_value);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = handle,
                        .priority = priority);
    struct tc_bpf *skel;
    int err;
    /* The hook (i.e. qdisc) may already exists because:
     *   1. it is created by other processes or users
     *   2. or since we are attaching to the TC ingress ONLY,
     *      bpf_tc_hook_destroy does NOT really remove the qdisc,
     *      there may be an egress filter on the qdisc
     */
    err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        return -1;
    }

    tc_opts.prog_fd = bpf_program__fd(progs[id]);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to attach TC: %d\n", err);
        return -1;
    }
    return 0;
}

int
bpf_skeleton::attach_special_programs()
{
    auto &meta_progs = meta_data.bpf_skel.progs;
    for (std::size_t i = 0; i < progs.size(); i++) {
        if (meta_progs[i].attach == "tc") {
            if (attach_tc_prog(i) != 0) {
                std::cerr << "failed to attach tc prog" << std::endl;
                return -1;
            }
        }
    }
    return 0;
}
}
