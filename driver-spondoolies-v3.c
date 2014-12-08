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

#ifdef WORDS_BIGENDIAN
#  define swap32tobe(out, in, sz)  ((out == in) ? (void)0 : memmove(out, in, sz))
#  define LOCAL_swap32be(type, var, sz)  ;
#  define swap32tole(out, in, sz)  swap32yes(out, in, sz)
#  define LOCAL_swap32le(type, var, sz)  LOCAL_swap32(type, var, sz)
#else
#  define swap32tobe(out, in, sz)  swap32yes(out, in, sz)
#  define LOCAL_swap32be(type, var, sz)  LOCAL_swap32(type, var, sz)
#  define swap32tole(out, in, sz)  ((out == in) ? (void)0 : memmove(out, in, sz))
#  define LOCAL_swap32le(type, var, sz)  ;
#endif

#define NTIME_OFFSET 0

static inline void swap32yes(void *out, const void *in, size_t sz)
{
	size_t swapcounter;

	for (swapcounter = 0; swapcounter < sz; ++swapcounter)
		(((uint32_t*)out)[swapcounter]) = swab32(((uint32_t*)in)[swapcounter]);
}

static void spondolies_handle_stale_jobs(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
    pthread_mutex_lock(&device->lock);
    int i = 0;
    for ( ; i < MAX_JOBS_IN_MINERGATE; i++) {
        if (device->my_jobs[i].cgminer_work != NULL &&
                strcmp(device->my_jobs[i].cgminer_work->job_id,
                    device->my_jobs[i].cgminer_work->pool->swork.job_id) != 0) {
#if 0
            struct work *work = device->my_jobs[i].cgminer_work;
            struct pool *pool = work->pool;
            /*
             * check that we still can work with merkles collision job
             * data
             */
            if (pool->coinbase_len != work->coinbase_len) {
                quit(1, "coinbase len changed work[%d] pool[%d]",
                        work->coinbase_len,
                        pool->coinbase_len);
            }
            if (pool->nonce2_offset != work->nonce2_offset) {
                quit(1, "coinbase nonce2_offset changed work[%d] pool[%d]",
                        work->nonce2_offset,
                        pool->nonce2_offset);
            }
            int i = 0;
            int j = 0;
            int k = 0;
            for (; i < pool->coinbase_len; ++i) {
                if (i >= pool->nonce2_offset && i < pool->nonce2_offset+8)
                    continue;
                if (pool->coinbase[i] != work->coinbase[i]) {
                    char *work_str;
                    char *pool_str;
                    work_str = bin2hex(work->coinbase, work->coinbase_len);
                    pool_str = bin2hex(pool->coinbase, work->coinbase_len);
                    printf("\nwork[%s]\n", work_str);
                    printf("pool[%s]\n", pool_str);
                    printf("     ");
                    for (k = 0;k < i; ++k) {
                        printf("--");
                    }
                    printf("^^\n");
                    applog(LOG_ERR, "found diff at position[%d] coinbase_len[%d] enonce_pos[%d]",
                            i,
                            pool->coinbase_len,
                            pool->nonce2_offset
                          );
                    free(work_str);
                    free(pool_str);
                }
            }
            if (pool->merkles != work->merkles) {
                quit(1, "merkles number changed work[%d] pool[%d]",
                        work->merkles,
                        pool->merkles);
            }
            for (i = 0; i < work->merkles; ++i) {
                for (j = 0; j < 32; ++j) {
                    if (work->merklebin[i*32+j] != pool->swork.merkle_bin[i][j]) {
                        char *work_str;
                        char *pool_str;
                        work_str = bin2hex(&work->merklebin[i*32], 32);
                        pool_str = bin2hex(pool->swork.merkle_bin[i], 32);
                        printf("\nwork[%s]\n", work_str);
                        printf("pool[%s]\n", pool_str);
                        printf("     ");
                        for (k = 0;k < j; ++k) {
                            printf("--");
                        }
                        printf("^^\n");
                        applog(LOG_ERR, "merkles found diff at position[%d][%d]", i, j);
                        free(work_str);
                        free(pool_str);
                        break;
                    }
                }
            }
            applog(LOG_ERR, "stale job!!! work id[%s], pool id[%s]",
                    device->my_jobs[i].cgminer_work->job_id,
                    device->my_jobs[i].cgminer_work->pool->swork.job_id);
#endif
            minergate_gen_packet stale_job;
            stale_job.header.message_type = MINERGATE_MESSAGE_TYPE_STALE_JOB;
            stale_job.header.message_size = sizeof(stale_job)-sizeof(stale_job.header);
            stale_job.header.protocol_version = MINERGATE_PROTOCOL_VERSION;
            stale_job.rsv[0] = device->my_jobs[i].cgminer_work->id;
            if (do_write(device->socket_fd, &stale_job, sizeof(stale_job)) != sizeof(stale_job)) {
                quit(1, "broken conneciton with miner");
            }
            applog(LOG_DEBUG, "discard previous job[%s]\n", device->my_jobs[i].cgminer_work->job_id);
            device->my_jobs[i].cgminer_work = NULL;
        }
    }
    pthread_mutex_unlock(&device->lock);
}

static int spondoolies_get_free_my_job_id(struct spond_adapter *device)
{
    int i = 0;
    int res = -1;
    pthread_mutex_lock(&device->lock);
    for ( ; i < MAX_JOBS_IN_MINERGATE; i++) {
        if (device->my_jobs[i].cgminer_work == NULL) {
            res = i;
            break;
        }
    }
    pthread_mutex_unlock(&device->lock);
    return res;
}

static struct work* spondoolies_get_work_by_job_id(struct spond_adapter *device, int my_job_id)
{
    int i = 0;
    struct work *work = NULL;
    pthread_mutex_lock(&device->lock);
    for ( ; i < MAX_JOBS_IN_MINERGATE; i++) {
        if (device->my_jobs[i].cgminer_work != NULL &&
            device->my_jobs[i].cgminer_work->id == my_job_id) {
            work = device->my_jobs[i].cgminer_work;
            break;
        }
    }
    pthread_mutex_unlock(&device->lock);
    return work;
}

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

static void fill_minergate_request(minergate_do_job_req* job, struct cgpu_info *cgpu, struct work *cg_work)
{
    int i;
	uint32_t converted[2];
    uint8_t bytes[8]; // ntime 32 bit, nbits 32 bit  
    struct spond_adapter *device = cgpu->device_data;
    struct pool *pool = cg_work->pool;
    /*
     * fill the job
     */
    memset(job, 0, sizeof(minergate_do_job_req));
    job->work_id_in_sw = cg_work->id;
    memcpy(
            bytes,
            cg_work->data + 4 /*bbversion*/ + 32 /*prev_hash*/ + 32 /*blank_merkle*/,
            4 /*ntime*/ + 4 /*nbits*/
            );
	LOCAL_swap32le(uint8_t, bytes, 2)
	swap32yes(converted, bytes, 2);
	job->timestamp  = ntohl(converted[0]+NTIME_OFFSET);
	job->difficulty = ntohl(converted[1]);
    memcpy(job->header_bin, pool->header_bin, sizeof(job->header_bin));
    /*
     * taking target and count leading zeros
     */
    unsigned char target[32];
	unsigned char target_swap[32];
    set_target(target, pool->sdiff);
    // order bytes, so we have bits from left to right
    swab256(target_swap, target);
    // set termination point
    target_swap[31] |= 0x01;
    job->leading_zeroes = 0;
    int pos = 0;
    while (((target_swap[pos / 8] >> (7 - (pos % 8))) & 0x1) == 0x0) {
        job->leading_zeroes++;
        pos++;
    }
    if (opt_debug) {
        char *target_str;
        target_str = bin2hex(target_swap, 32);
        applog(LOG_DEBUG, "stratum target[%s] work_difficulty[%f] job->leading_zeroes[%d]\n",
                target_str,
                cg_work->work_difficulty,
                job->leading_zeroes
              );
        free(target_str);
    }
    job->ntime_limit = 0; //? not sure we need it
    job->ntime_offset = NTIME_OFFSET; //? not sure we need it
    job->resr1 = 0;
    job->coinbase_len = pool->coinbase_len;
    memcpy(job->coinbase, pool->coinbase, job->coinbase_len);
    job->nonce2_offset = pool->nonce2_offset;
    job->merkles = pool->merkles;
    // each merkle is 32 bytes size
	for (i = 0; i < pool->merkles; ++i) {
		memcpy(job->merkle + 32 * i, pool->swork.merkle_bin[i], 32);
	}
}

static int polling_and_return_number_of_wins(struct thr_info *thr)
{
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    /*
     * send request to miner gateway to get wins results
     */
    minergate_gen_packet req_rsp;
    req_rsp.header.message_type = MINERGATE_MESSAGE_TYPE_RSP_REQ;
    req_rsp.header.message_size = sizeof(req_rsp)-sizeof(req_rsp.header);
    req_rsp.header.protocol_version = MINERGATE_PROTOCOL_VERSION;
    do_write(device->socket_fd, &req_rsp, sizeof(req_rsp)); 
    /* 
     * read result
     */
    // OK, since we don't know message size, lets take biggest
    void *message = calloc(1, sizeof(minergate_rsp_packet));
    int size =  do_read_packet(device->socket_fd, message, sizeof(minergate_rsp_packet));
    if (size == 0) {
        quit(1, "%s: Ooops returned bad packet from cgminer", spondooliesv3_drv.dname);
        free(message);
        return 0;
    }
    // lets check the header
    minergate_packet_header *header = (minergate_packet_header*) message;
    switch (header->message_type) {
        case MINERGATE_MESSAGE_TYPE_RSP_NODATA:
            {
                free(message);
                return 0;
            }
        case MINERGATE_MESSAGE_TYPE_RSP_DATA:
            {
                int i;
                int j;
                minergate_rsp_packet *rsp = (minergate_rsp_packet*) message;
                // TODO: handle rsp->gh_div_10_rate
                int results = rsp->rsp_count;
                for (i = 0; i < results; ++i) {
                    // get work object that requested mining
                    struct work *work = spondoolies_get_work_by_job_id(device, rsp->rsp[i].work_id_in_sw);
                    if (work == NULL) {
                        free(message);
                        return 0;
                    }
                    /*
                     * calucating merkle root for work data,
                     * code taken from cgminer - gen_stratum_work
                     *
                     * TODO: since this already done in miner, we may pass data in message
                     *       to reduce CPU time
                     */
                    unsigned char merkle_root[32], merkle_sha[64];
                    uint32_t *data32, *swap32;
                    uint8_t coinbase[work->coinbase_len];
                    uint64_t nonce2le = htole64(rsp->rsp[i].nonce2);
                    memcpy(coinbase, work->coinbase, work->coinbase_len);
                    work->nonce2_len = rsp->rsp[i].nonce2_len;
                    work->nonce2 = rsp->rsp[i].nonce2;
                    memcpy(coinbase + work->nonce2_offset, &nonce2le, work->nonce2_len);
                    gen_hash(coinbase, merkle_root, work->coinbase_len);
                    memcpy(merkle_sha, merkle_root, 32);
                    for (j = 0; j < work->merkles; j++) {
                        memcpy(merkle_sha + 32,  work->merklebin + j * 32, 32);
                        gen_hash(merkle_sha, merkle_root, 64);
                        memcpy(merkle_sha, merkle_root, 32);
                    }
                    data32 = (uint32_t *)merkle_sha;
                    swap32 = (uint32_t *)merkle_root;
                    flip32(swap32, data32);
                    memcpy(work->data + 4 /*bbversion*/ + 32 /*prev_hash*/, merkle_root, 32);
                    if (!submit_nonce(work->thr, work, ntohl(rsp->rsp[i].winner_nonce))) {
                        quit(1, "%s: win [%d/%d] enonce[%016llx] nonce [%08x]",
                                spondooliesv3_drv.dname,
                                i+1,
                                results,
                                rsp->rsp[i].nonce2,
                                rsp->rsp[i].winner_nonce
                            );
                    }
                }
                free(message);
                return results;
            };
        default:
            {
                applog(LOG_ERR, "%s: Ooops returned un expected message type [%08x]",
                        spondooliesv3_drv.dname,
                        header->message_type);
                free(message);
                return 0;
            }
    }
    return 0;
}

static int64_t spond_scanhash(struct thr_info *thr)
{
    polling_and_return_number_of_wins(thr);
    return 50000; // TODO: temporary value, must be
                  //       calculated from miner
}

static void spondoolies_shutdown(__maybe_unused struct thr_info *thr)
{
}

static void spond_flush_work(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
    spondolies_handle_stale_jobs(cgpu);
}

static bool spondoolies_queue_full(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
    struct work *work = NULL;
    struct pool *pool = NULL;
    int id = 0;
#if 0    
    spondolies_handle_stale_jobs(cgpu);
#endif
    /*
     * Lets check that if we can accept new job
     */
    id = spondoolies_get_free_my_job_id(device);
    if (id <0) {
        return true;
    }
    /*
     * get the work and initialize work thread data
     */
    work = get_queued(cgpu);
    if (work == NULL) {
        return false;
    }
    work->thr = cgpu->thr[0];
    work->thr_id = cgpu->thr[0]->id;
    assert(work->thr);
    work->subid = 0;
    applog(LOG_NOTICE, "new work job_id[%s]", work->job_id);
    /*
     * check that pool request is correct
     */
    pool = work->pool;
    if (!pool->has_stratum) {
        quit(1, "%s: Miner Manager have to use stratum pool", spondooliesv3_drv.dname);
    }
    if (pool->coinbase_len > SPOND_MAX_COINBASE_LEN) {
        applog(LOG_ERR, "%s: Miner Manager pool coinbase length[%d] have to less then %d",
                spondooliesv3_drv.dname,
                pool->coinbase_len,
                SPOND_MAX_COINBASE_LEN);
        return false;
    }
    if (pool->merkles > SPOND_MAX_MERKLES) {
        applog(LOG_ERR, "%s: Miner Manager merkles have to less then %d",
                spondooliesv3_drv.dname,
                SPOND_MAX_MERKLES);
        return false;
    }
    /*
     * fill job and send it to miner
     */
    minergate_req_packet req_packet;
    memset(&req_packet, 0, sizeof(req_packet));
    req_packet.header.protocol_version = MINERGATE_PROTOCOL_VERSION;
    req_packet.header.message_type = MINERGATE_MESSAGE_TYPE_JOB_REQ;
    req_packet.header.message_size = sizeof(req_packet)-sizeof(req_packet.header);
    // TODO: use MACRO
    req_packet.mask = 0x01; // 0x01 = first request, 0x2 = drop old work
    req_packet.req_count = 1; // one job only
    // currently we will send only one job
    cg_wlock(&pool->data_lock);
    fill_minergate_request(&req_packet.req[0], cgpu, work);
    cg_wunlock(&pool->data_lock);
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
            return false;
    }
    /*
     * everything is ok, we cache the job
     */
    pthread_mutex_lock(&device->lock);
    device->my_jobs[id].cgminer_work = work;
    pthread_mutex_unlock(&device->lock);
    return true;
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
	.queue_full = spondoolies_queue_full,
};
