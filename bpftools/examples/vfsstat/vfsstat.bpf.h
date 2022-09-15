// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
#ifndef __VFSSTAT_H
#define __VFSSTAT_H

struct event {
    int read/s;
    int write/s;
    int fsync/s;
    int open/s;
    int create/s;
}

#endif /* __VFSSTAT_H */
