/*
 * Copyright 2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2014 Zvi Shteingart - Spondoolies-tech.com
 * Copyright 2014 Dmitry (Dima) Kuzminov - Spondoolies-tech.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#ifndef __DRIVER_SPONDOOLIES_V3_H__
#define __DRIVER_SPONDOOLIES_V3_H__

#include "miner.h"
#include "mg_proto_parser-v3.h"

#define MAX_JOBS_IN_MINERGATE   1 

typedef struct {
    struct work*     cgminer_work;
} spond_driver_work;

struct spond_adapter {
    pthread_mutex_t     lock;
    void*               cgpu;
    int                 socket_fd;
    spond_driver_work   my_jobs[MAX_JOBS_IN_MINERGATE];
};

#endif //__DRIVER_SPONDOOLIES_V3_H__
