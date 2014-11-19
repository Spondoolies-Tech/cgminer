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

static void fill_minergate_request(minergate_do_job_req* job, struct thr_info *thr)
{
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    struct pool *pool = current_pool();
    uint64_t difficulty_64bit = round(pool->sdiff);
    /*
     * fill the job
     */
    memset(job, 0, sizeof(minergate_do_job_req));
    job->work_id_in_sw = 0; // TODO: not sure we really need it
    job->difficulty = 0; // TODO: not sure we really need it
    job->timestamp = 0; // TODO: not sure we really need it
    /*
     * leading zeros strange logic, taken from previous ??
     */
    job->leading_zeroes = 30;
    while (difficulty_64bit) {
        job->leading_zeroes++;
        difficulty_64bit = difficulty_64bit >> 1;
    }
    job->ntime_limit = 0; //? not sure we need it
    job->ntime_offset = 0; //? not sure we need it
    job->resr1 = 0;
    job->coinbase_len = pool->coinbase_len;
    memcpy(job->coinbase, pool->coinbase, job->coinbase_len);
    job->nonce2_offset = pool->nonce2_offset;
    job->merkles = pool->merkles;
    // each merkle is 32 bytes size
    memcpy(job->merkle, pool->merklebin, (job->merkles<<5));
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
            applog(LOG_ERR, "%s: Miner Manager pool coinbase length[%d] have to less then %d",
                    spondooliesv3_drv.dname,
                    pool->coinbase_len,
                    SPOND_MAX_COINBASE_LEN);
            return 0;
        }
        if (pool->merkles > SPOND_MAX_MERKLES) {
            applog(LOG_ERR, "%s: Miner Manager merkles have to less then %d",
                    spondooliesv3_drv.dname,
                    SPOND_MAX_MERKLES);
            return 0;
        }
        /*
         * fill job and send it to miner
         */
        minergate_req_packet req_packet;
        memset(&req_packet, 0, sizeof(req_packet));
        req_packet.header.protocol_version = MINERGATE_PROTOCOL_VERSION;
        req_packet.header.message_type = MINERGATE_MESSAGE_TYPE_JOB_REQ;
        req_packet.header.message_size = sizeof(req_packet)-sizeof(req_packet.header);
        // TODO: use or remove
        req_packet.requester_id = 0;
        // TODO: use or remove
        req_packet.request_id = 0;
        // TODO: use MACRO
        req_packet.mask = 0x01; // 0x01 = first request, 0x2 = drop old work
        req_packet.req_count = 1; // one job only
        // currently we will send only one job
        fill_minergate_request(&req_packet.req[0], thr);
        do_write(device->socket_fd, &req_packet, sizeof(req_packet));
        /*
         * read the response from miner
         */
        minergate_gen_packet rsp_packet;
        uint32_t size = 0;
        if ((size = do_read_packet(device->socket_fd, &rsp_packet, sizeof(rsp_packet))) != sizeof(rsp_packet)) {
            quit(1, "%s: critical error, packet sent from miner is bad received size[%u] expected [%u], quiting...",
                    spondooliesv3_drv.dname,
                    size,
                    sizeof(rsp_packet)
                    );
            return 0;
        }
        switch (rsp_packet.header.message_type) {
            case MINERGATE_MESSAGE_TYPE_JOB_REQ_ACK:
                applog(LOG_DEBUG, "%s MINERGATE_MESSAGE_TYPE_JOB_REQ_ACK", spondooliesv3_drv.dname);
                break;
            case MINERGATE_MESSAGE_TYPE_JOB_REQ_REJ:
                applog(LOG_DEBUG, "%s MINERGATE_MESSAGE_TYPE_JOB_REQ_REJ", spondooliesv3_drv.dname);
                break;
            default:
                applog(LOG_ERR, "%s unexpected type[%x]", spondooliesv3_drv.dname, rsp_packet.header.message_type);
                return 0;
        }
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
    // TODO: we may not need this function
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
