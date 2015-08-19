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

#ifndef __DRIVER_SPONDOOLIES_SP60_H__
#define __DRIVER_SPONDOOLIES_SP60_H__

#include "miner.h"
#include "driver-spondoolies-sp60-p.h"

#define MAX_JOBS_IN_MINERGATE            50 // calculated from asic capabilties
#define MAX_SW_JOB_INDEX_IN_MINERGATE    (MAX_JOBS_IN_MINERGATE<<4)
#define NTIME_LIMIT                     7000

typedef struct {
    uint32_t    sw_job_id;
	cglock_t    data_lock;
	struct pool pool;
} spond_driver_work;

struct spond_adapter {
	pthread_mutex_t     lock;
	void*               cgpu;
	int                 socket_fd;
    spond_driver_work   my_jobs[MAX_JOBS_IN_MINERGATE];
    uint32_t            current_job_id;
    int                 drop_old_jobs;
	time_t              last_stats;
};

#endif //__DRIVER_SPONDOOLIES_SP60_H__
