/*
 * Copyright 2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2014 Zvi (Zvisha) Shteingart - Spondoolies-tech.com
 * Copyright 2014 Dmitry (Dima) Kuzminov - Spondoolies-tech.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

/*
   This driver communicates the job requests via Unix socket to the minergate
   process, that is responsible for controlling the Spondoolies Dawson SP10 miner.

   The jobs sent each with unique ID and returned asynchronously in one of the next
   transactions. REQUEST_PERIOD and REQUEST_SIZE define the communication rate with minergate.
   */
#include <float.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

#include "config.h"

#ifdef WIN32
#include <windows.h>
#endif

#include "compat.h"
#include "miner.h"
#include "mg_proto_parser-v3.h"
#include "driver-spondoolies-v3.h"

static struct api_data *spondoolies_api_stats(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
    struct api_data *root = NULL;
    // TODO: need to ensure that params filled
    root = api_add_int(root, "ASICs total rate", &device->temp_rate, false);
    root = api_add_int(root, "Temparature rear", &device->rear_temp, false);
    root = api_add_int(root, "Temparature front", &device->front_temp, false);
    return root;
}

static int init_socket()
{
    int socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    if (socket_fd < 0) {
        applog(LOG_ERR, "%s: socket error[%d][%s]",
                spondooliesv3_drv.dname,
                errno,
                strerror(errno));
        return 0;
    }
    /* start with a clean address structure */
    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, MINERGATE_SOCKET_FILE);
    if(connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un))) {
        applog(LOG_ERR, "%s: socket connect error[%d][%s]",
                spondooliesv3_drv.dname,
                errno,
                strerror(errno));
        return 0;
    }
    return socket_fd;
}

static void spondoolies_detect(__maybe_unused bool hotplug)
{
    struct cgpu_info *cgpu = calloc(1, sizeof(struct cgpu_info));
    struct device_drv *drv = &spondooliesv3_drv;
    struct spond_adapter *device;
    assert(cgpu);
    cgpu->drv = drv;
    cgpu->deven = DEV_ENABLED;
    cgpu->threads = 1;
    cgpu->device_data = calloc(1, sizeof(struct spond_adapter));
    assert(cgpu->device_data);
    device = cgpu->device_data;
    device->cgpu = (void *)cgpu;
    // TODO: ??
    device->adapter_state = ADAPTER_STATE_OPERATIONAL;
    // TODO: ??
    device->mp_next_req = allocate_minergate_packet_req_v3(0xca, 0xfe);
    // TODO: ??
    device->mp_last_rsp = allocate_minergate_packet_rsp_v3(0xca, 0xfe);
    pthread_mutex_init(&device->lock, NULL);
    device->socket_fd = init_socket();
    if (device->socket_fd < 1) {
        quit(1, "Error connecting to minergate server!");
    }
    assert(add_cgpu(cgpu));
    applog(LOG_DEBUG, "%s %s done", spondooliesv3_drv.dname, __FUNCTION__);
}

static void spondoolies_init(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
    // TODO: we need forward this request to our miner
    applog(LOG_DEBUG, "%s %s done", spondooliesv3_drv.dname, __FUNCTION__);
}

static bool spondoolies_prepare(struct thr_info *thr)
{
    struct cgpu_info *spondoolies = thr->cgpu;
    struct timeval now;
    assert(spondoolies);
    cgtime(&now);
    // TODO: do we want send special message to miner??
    applog(LOG_DEBUG, "%s %s done", spondooliesv3_drv.dname, __FUNCTION__);
    return true;
}

static void fill_minergate_request(minergate_do_job_req* work, struct thr_info *thr)
{
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    struct pool *pool = current_pool();
    // TODO: fill message
}

static void polling(struct thr_info *thr)
{
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    // TODO: request wins from miner
}

static int64_t spond_scanhash(struct thr_info *thr)
{
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    struct pool *pool = current_pool();
    if (thr->work_restart || thr->work_update) {
        applog(LOG_DEBUG, "%s: restart: %d, update: %d",
                spondooliesv3_drv.dname,
                thr->work_restart,
                thr->work_update);
        /*
         * set states of cgminer to false
         */
        thr->work_update = false;
        thr->work_restart = false;
        /*
         * Make sure pool is ready, get_work is blocking funciton
         * and never returns NULL
         */
        get_work(thr, thr->id);
        /*
         * check that pool request is correct
         */
        if (!pool->has_stratum) {
            quit(1, "%s: Miner Manager have to use stratum pool", spondooliesv3_drv.dname);
        }
        if (pool->coinbase_len > SPOND_MAX_COINBASE_LEN) {
            applog(LOG_ERR, "%s: Miner Manager pool coinbase length have to less then %d",
                    spondooliesv3_drv.dname,
                    SPOND_MAX_COINBASE_LEN);
            return 0;
        }
        if (pool->merkles > SPOND_MAX_MERKLES) {
            applog(LOG_ERR, "%s: Miner Manager merkles have to less then %d",
                    spondooliesv3_drv.dname,
                    SPOND_MAX_MERKLES);
            return 0;
        }
        // TODO: fill job and send it to miner
    }
    polling(thr);
    // TODO: return wins number
    return 0;
}

static void spondoolies_shutdown(__maybe_unused struct thr_info *thr)
{
}

static void spond_flush_work(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
    mutex_lock(&device->lock);
    device->reset_mg_queue = 3;
    mutex_unlock(&device->lock);
}

struct device_drv spondooliesv3_drv = {
    .drv_id = DRIVER_spondooliesv3,
    .dname = "Spondoolies-V3",
    .name = "SP3",
    .get_api_stats = spondoolies_api_stats,
    .drv_detect = spondoolies_detect,
    .reinit_device = spondoolies_init,
    .thread_prepare = spondoolies_prepare,
    .hash_work = hash_queued_work,
    .scanwork = spond_scanhash,
    .thread_shutdown = spondoolies_shutdown,
    .flush_work = spond_flush_work,
};
