#! /bin/sh

# Copyright 2017 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 10-Apr-2017   Brendan Gregg   Created this.

./bpftool btf dump file ${1:-/sys/kernel/btf/vmlinux} format c
