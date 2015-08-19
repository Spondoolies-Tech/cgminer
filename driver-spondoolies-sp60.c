/*
 * Copyright 2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2014 Zvi (Zvisha) Shteingart - Spondoolies-tech.com
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
#include "driver-spondoolies-sp60-p.h"
#include "driver-spondoolies-sp60.h"
#include "crc.h"

#define SPONDLOG(LOGLEVEL, fmt, args...)              \
    do {                                              \
        applog(LOGLEVEL,                              \
            "[%s:%d(%s)] "fmt,                        \
            sp60_drv.dname,                           \
            __LINE__,                                 \
            __FUNCTION__,                             \
            ##args                                    \
        );                                            \
    } while (0)

#ifdef WORDS_BIGENDIAN
#  define LOCAL_swap32le(type, var, sz)  LOCAL_swap32(type, var, sz)
#else
#  define LOCAL_swap32le(type, var, sz)  ;
#endif

static inline void swap32yes(void *out, const void *in, size_t sz)
{
    size_t swapcounter;

    for (swapcounter = 0; swapcounter < sz; ++swapcounter)
        (((uint32_t*)out)[swapcounter]) = swab32(((uint32_t*)in)[swapcounter]);
}

static int init_socket(void)
{
    int socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    if (socket_fd < 0) {
        SPONDLOG(LOG_ERR, "socket error[%d][%s]", errno, strerror(errno));
        return 0;
    }
    /* start with a clean address structure */
    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, pxgate_SOCKET_FILE);
    if(connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un))) {
        SPONDLOG(LOG_ERR, "socket connect error[%d][%s]", errno, strerror(errno));
        return 0;
    }
    return socket_fd;
}

static int get_array_id(uint32_t job_id)
{
    return job_id % MAX_JOBS_IN_MINERGATE;
}

static void fill_pxgate_request(pxgate_do_mrkljob_req* job, struct cgpu_info *cgpu)
{
    int i;
    uint32_t converted[2];
    uint8_t bytes[8]; // ntime 32 bit, nbits 32 bit  
    struct spond_adapter *device = cgpu->device_data;
    int sw_job_id = device->current_job_id;
    int job_id = get_array_id(sw_job_id);
    struct pool *pool = &device->my_jobs[job_id].pool;
    cg_rlock(&device->my_jobs[job_id].data_lock);
    /*
     * fill the job
     */
    memset(job, 0, sizeof(pxgate_do_mrkljob_req));
    job->work_id_in_sw = sw_job_id; 
    memcpy(
            bytes,
            pool->header_bin + 4 /*bbversion*/ + 32 /*prev_hash*/ + 32 /*blank_merkle*/,
            4 /*ntime*/ + 4 /*nbits*/
          );
    LOCAL_swap32le(uint8_t, bytes, 2)
        swap32yes(converted, bytes, 2);
    job->timestamp  = ntohl(converted[0]);
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
    printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
    while (((target_swap[pos / 8] >> (7 - (pos % 8))) & 0x1) == 0x0) {
        job->leading_zeroes++;
        pos++;
    }
    if (opt_debug) {
        char *target_str;
        target_str = bin2hex(target_swap, 32);
        SPONDLOG(LOG_DEBUG, "stratum target[%s] job->leading_zeroes[%d]\n",
                target_str,
                job->leading_zeroes
              );
        free(target_str);
    }
    job->ntime_limit = NTIME_LIMIT; 
    job->resr1 = 0;
    job->coinbase_len = pool->coinbase_len;
    memcpy(job->coinbase, pool->coinbase, job->coinbase_len);
    job->nonce2_offset = pool->nonce2_offset;
    if (pool->n2size < 8) {
        printf("ERROR: NONCE2 TOO SMALL (%d)!\n", pool->n2size);
        passert(0);
    }
    job->merkles = pool->merkles;
    // each merkle is 32 bytes size
    for (i = 0; i < pool->merkles; ++i) {
        memcpy(job->merkle + 32 * i, pool->swork.merkle_bin[i], 32);
    }
    cg_runlock(&device->my_jobs[job_id].data_lock);
}

static void spondoolies_detect_sp60(__maybe_unused bool hotplug)
{
    struct cgpu_info *cgpu = calloc(1, sizeof(struct cgpu_info));
    struct device_drv *drv = &sp60_drv;
    struct spond_adapter *device;
    int i;
    printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
    assert(cgpu);
    cgpu->drv = drv;
    cgpu->deven = DEV_ENABLED;
    cgpu->threads = 1;
    cgpu->device_data = calloc(1, sizeof(struct spond_adapter));
    assert(cgpu->device_data);
    device = cgpu->device_data;
    device->cgpu = (void *)cgpu;
    device->current_job_id = 0;;
    pthread_mutex_init(&device->lock, NULL);
    device->socket_fd = init_socket();
    for (i = 0 ; i < MAX_JOBS_IN_MINERGATE; i++) {
        // clean structure
        memset(&device->my_jobs[i], 0, sizeof(spond_driver_work));
        // init our internal lock
        cglock_init(&(device->my_jobs[i].data_lock));
        // init lock for cgminer needs (make sure we are not broken)
        cglock_init(&(device->my_jobs[i].pool.data_lock));
    }
    if (device->socket_fd < 1) {
        quit(1, "Error connecting to minergate server!");
    }
    assert(add_cgpu(cgpu));
    // setup time
	device->last_stats = time(NULL);
    SPONDLOG(LOG_DEBUG, "done");
}

static int polling_and_return_number_of_wins(struct thr_info *thr)
{
    //    printf("########### %d\n", __LINE__);
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    /*
     * send request to miner gateway to get wins results
     */
    pxgate_gen_packet req_rsp;
    req_rsp.header.message_type = pxgate_MESSAGE_TYPE_RSP_REQ;
    req_rsp.header.message_size = sizeof(req_rsp)-sizeof(req_rsp.header);
    req_rsp.header.protocol_version = pxgate_PROTOCOL_VERSION;
    do_write(device->socket_fd, &req_rsp, sizeof(req_rsp)); 
    /* 
     * read result
     */
    // OK, since we don't know message size, lets take biggest
    void *message = calloc(1, sizeof(pxgate_rsp_packet));
    int size =  do_read_packet(device->socket_fd, message, sizeof(pxgate_rsp_packet));
    if (size == 0) {
        quit(1, "%s: Ooops returned bad packet from cgminer", sp60_drv.dname);
        free(message);
        return 0;
    }
    // lets check the header
    pxgate_packet_header *header = (pxgate_packet_header*) message;
    switch (header->message_type) {
        case pxgate_MESSAGE_TYPE_RSP_NODATA:
            {
                free(message);
                //printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
                return 0;
            }
        case pxgate_MESSAGE_TYPE_RSP_DATA:
            {
                int i;
                int j;
                pxgate_rsp_packet *rsp = (pxgate_rsp_packet*) message;
                // TODO: handle rsp->gh_div_10_rate
                int results = rsp->rsp_count;
                for (i = 0; i < results; ++i) {
                    // get work object that requested mining
                    struct pool *real_pool = NULL;
                    struct pool *pool = NULL;
                    int job_id = get_array_id(rsp->rsp[i].work_id_in_sw);
                    // lets check that we can work with sw job_id and pool we cached
                    // CHECKING JOB VALIDITY
                    if (job_id < 0 || rsp->rsp[i].work_id_in_sw > MAX_SW_JOB_INDEX_IN_MINERGATE) {
                        free(message);
                        printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
                        return 0;
                    }
                    cg_rlock(&(device->my_jobs[job_id].data_lock));
                    if (device->my_jobs[job_id].pool.swork.job_id == NULL) {
                        // it is stale job, we drop result
                        // it happens due to flush work, right before we received results from asic
                        SPONDLOG(LOG_ERR, "droping wins enonce2[0x%016llx] nonce[0x%08x] gate_job_id[%d] cgminer_job_id[%d], stale job",
                                rsp->rsp[i].nonce2,
                                rsp->rsp[i].winner_nonce,
                                rsp->rsp[i].work_id_in_sw,
                                device->my_jobs[job_id].sw_job_id
                                );
                        free(message);
                        cg_runlock(&(device->my_jobs[job_id].data_lock));
                        return 0;
                    }
                    if (device->my_jobs[job_id].sw_job_id != rsp->rsp[i].work_id_in_sw) {
                        // it is stale job, we drop result
                        SPONDLOG(LOG_ERR, "droping wins enonce2[0x%016llx] nonce[0x%08x] gate_job_id[%d] cgminer_job_id[%d], stale job",
                                rsp->rsp[i].nonce2,
                                rsp->rsp[i].winner_nonce,
                                rsp->rsp[i].work_id_in_sw,
                                device->my_jobs[job_id].sw_job_id
                                );
                        free(message);
                        cg_runlock(&(device->my_jobs[job_id].data_lock));
                        return 0;
                    }
                    // JOB VALIDITY PASSED
                        printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
                    pool = &device->my_jobs[job_id].pool;
                        printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
                    real_pool = pools[device->my_jobs[job_id].pool.pool_no];
                        printf("\n\n############ [%s:%d](%s)   real_pool[%p] pool_no[%d]\n\n",
                                __FILE__, __LINE__, __FUNCTION__,
                                real_pool, device->my_jobs[job_id].pool.pool_no );
                    if (submit_nonce2_nonce(
                                thr,
                                pool,
                                real_pool,
                                rsp->rsp[i].nonce2,
                                ntohl(rsp->rsp[i].winner_nonce),
                                rsp->rsp[i].ntime_offset)){
                        printf("ERROR NONCE::: %s: win [%d/%d] enonce[%016llx] nonce [%08x], ntime_offset %x",
                                sp60_drv.dname,
                                i+1,
                                results,
                                rsp->rsp[i].nonce2,
                                rsp->rsp[i].winner_nonce,
                                rsp->rsp[i].ntime_offset
                              );
                    }
                        printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
                    cg_runlock(&(device->my_jobs[job_id].data_lock));
                }
                printf("########### %d\n", __LINE__);
                free(message);
                //                printf("########### DONE %d\n", __LINE__);
                return results;
            };
        default:
            {
                SPONDLOG(LOG_ERR, "Ooops returned un expected message type [%08x]", header->message_type);
                free(message);
                return 0;
            }
    }
    return 0;
}

// Return completed work to submit_nonce() and work_completed()
// struct timeval last_force_queue = {0};
static int64_t spond_scanhash_sp60(struct thr_info *thr)
{
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
	time_t now_t = time(NULL);
	/* Poll stats only once per second */
    if (now_t != device->last_stats) {
        device->last_stats = now_t;
        pthread_mutex_lock(&device->lock);
        polling_and_return_number_of_wins(thr);
        pthread_mutex_unlock(&device->lock);
        // TODO: real data should be used
        //       currently on POC we have 160 Mhashes
        return 160000000;
    }
    return 0;
}

static void free_pool_stratum(struct spond_adapter* spond, int job_id)
{
    struct pool *pool = &spond->my_jobs[job_id].pool;
    free(pool->swork.job_id);
    free(pool->nonce1);
    free(pool->coinbase);
    pool->swork.job_id = NULL;
    pool->nonce1 = NULL;
    pool->coinbase = NULL;
}

static void spond_drop_job(struct spond_adapter *device, uint32_t job_id_index)
{
    cg_wlock(&(device->my_jobs[job_id_index].data_lock));
    if (device->my_jobs[job_id_index].pool.swork.job_id != NULL) {
        SPONDLOG(LOG_INFO, "discard previous job[%d] pool.swork.job_id[%s]\n",
                device->my_jobs[job_id_index].sw_job_id,
                device->my_jobs[job_id_index].pool.swork.job_id);
        free_pool_stratum(device, job_id_index);
    }
    cg_wunlock(&(device->my_jobs[job_id_index].data_lock));
}

static void spond_flush_work_sp60(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
    printf("############ [%s:%d](%s)\n", __FILE__, __LINE__, __FUNCTION__);
    pthread_mutex_lock(&device->lock);
    int i;
    device->drop_old_jobs = 1;
    for (i = 0 ; i < MAX_JOBS_IN_MINERGATE; i++) {
        spond_drop_job(device, i);
    }
    // reset queue pos
    device->current_job_id = 0;
    pthread_mutex_unlock(&device->lock);
}

static void copy_pool_stratum(struct spond_adapter* spond, struct pool *pool)
{
    int i;
    int merkles = pool->merkles;
    size_t coinbase_len = pool->coinbase_len;
    struct pool *pool_stratum = &spond->my_jobs[get_array_id(spond->current_job_id)].pool;

    if (pool_stratum->swork.job_id != NULL) {
        spond_drop_job(spond, get_array_id(spond->current_job_id));
        SPONDLOG(LOG_DEBUG, "discarding pool->swork.job_id[%s], sw_job_id[%d]",
                pool_stratum->swork.job_id, spond->my_jobs[get_array_id(spond->current_job_id)].sw_job_id);
    }

    cg_wlock(&(spond->my_jobs[get_array_id(spond->current_job_id)].data_lock));
    // lets write down sw job id
    spond->my_jobs[get_array_id(spond->current_job_id)].sw_job_id = spond->current_job_id;

    free_pool_stratum(spond, get_array_id(spond->current_job_id));

    pool_stratum->coinbase = cgcalloc(coinbase_len, 1);
    memcpy(pool_stratum->coinbase, pool->coinbase, coinbase_len);

    for (i = 0; i < pool_stratum->merkles; i++)
        free(pool_stratum->swork.merkle_bin[i]);
    if (merkles) {
        pool_stratum->swork.merkle_bin = cgrealloc(pool_stratum->swork.merkle_bin,
                sizeof(char *) * merkles + 1);
        for (i = 0; i < merkles; i++) {
            pool_stratum->swork.merkle_bin[i] = cgmalloc(32);
            memcpy(pool_stratum->swork.merkle_bin[i], pool->swork.merkle_bin[i], 32);
        }
    }

    pool_stratum->sdiff = pool->sdiff;
    pool_stratum->coinbase_len = pool->coinbase_len;
    pool_stratum->nonce2_offset = pool->nonce2_offset;
    pool_stratum->n2size = pool->n2size;
    pool_stratum->merkles = pool->merkles;

    pool_stratum->swork.job_id = strdup(pool->swork.job_id);
    pool_stratum->nonce1 = strdup(pool->nonce1);

    memcpy(pool_stratum->ntime, pool->ntime, sizeof(pool_stratum->ntime));
    memcpy(pool_stratum->header_bin, pool->header_bin, sizeof(pool_stratum->header_bin));
    cg_wunlock(&(spond->my_jobs[get_array_id(spond->current_job_id)].data_lock));
}

static void spondoolies_update_work_sp60(struct cgpu_info *cgpu)
{
    struct spond_adapter *device = cgpu->device_data;
	struct thr_info *thr = cgpu->thr[0];
    struct work *work = NULL;
    struct pool *pool = NULL;

    // setup thread flags
    SPONDLOG(LOG_DEBUG, "New stratum: restart: %d, update: %d", thr->work_restart, thr->work_update);
	thr->work_update = false;
	thr->work_restart = false;

	work = get_work(thr, thr->id); /* Make sure pool is ready */
	discard_work(work); /* Don't leak memory */

    // lets check pool job parameters
    pool = current_pool();
    if (!pool->has_stratum) {
        quit(1, "%s: Miner Manager have to use stratum pool", sp60_drv.dname);
    }
    if (pool->coinbase_len > SPOND_MAX_COINBASE_LEN) {
        SPONDLOG(LOG_ERR, "Miner Manager pool coinbase length[%d] have to less then %d",
                pool->coinbase_len,
                SPOND_MAX_COINBASE_LEN);
        return;
    }
    if (pool->merkles > SPOND_MAX_MERKLES) {
        SPONDLOG(LOG_ERR, "Miner Manager merkles have to less then %d", SPOND_MAX_MERKLES);
        return;
    }
    // need to lock driver, since we may drop all jobs
    // #########   DEVICE LOCK
    //
    pthread_mutex_lock(&device->lock);
    // lock and copy pool data
    // in our case pool_no is always same number
    // but swork.job_id changes each job
    cg_rlock(&pool->data_lock);
    copy_pool_stratum(device, pool);
    cg_runlock(&pool->data_lock);
    /*
     * fill job and send it to miner
     */
    pxgate_req_packet req_packet;
    memset(&req_packet, 0, sizeof(req_packet));
    req_packet.header.protocol_version = pxgate_PROTOCOL_VERSION;
    req_packet.header.message_type = pxgate_MESSAGE_TYPE_JOB_REQ;
    req_packet.header.message_size = sizeof(req_packet)-sizeof(req_packet.header);
    // TODO: use MACRO
    req_packet.mask = 0x01; // 0x01 = first request, 0x2 = drop old work
    if (device->drop_old_jobs) {
        req_packet.mask |= 0x02; // drop old work
        device->drop_old_jobs  = 0;
    }
    // currently we will send only one job
    fill_pxgate_request(&req_packet.req, cgpu);
    // #########   DEVICE UNLOCK
    //
    pthread_mutex_unlock(&device->lock);
    do_write(device->socket_fd, &req_packet, sizeof(req_packet));
    /*
     * read the response from miner
     */
    pxgate_gen_packet rsp_packet;
    uint32_t size = 0;
    if ((size = do_read_packet(device->socket_fd, &rsp_packet, sizeof(rsp_packet))) != sizeof(rsp_packet)) {
        quit(1, "%s: critical error, packet sent from miner is bad received size[%u] expected [%u], quiting...",
                sp60_drv.dname,
                size,
                sizeof(rsp_packet)
            );
    }
    switch (rsp_packet.header.message_type) {
        case pxgate_MESSAGE_TYPE_JOB_REQ_ACK:
            SPONDLOG(LOG_DEBUG, "pxgate_MESSAGE_TYPE_JOB_REQ_ACK");
            break;
        case pxgate_MESSAGE_TYPE_JOB_REQ_REJ:
            SPONDLOG(LOG_DEBUG, "pxgate_MESSAGE_TYPE_JOB_REQ_REJ");
            break;
        default:
            SPONDLOG(LOG_ERR, "unexpected type[%x]", rsp_packet.header.message_type);
            return;
    }
    /*
     * everything is ok, we cache the job
     */
    device->current_job_id = (device->current_job_id++) % MAX_SW_JOB_INDEX_IN_MINERGATE;
}

struct device_drv sp60_drv = {
    .drv_id          = DRIVER_sp60,
    .dname           = "sp60",
    .name            = "S60",
    .drv_detect      = spondoolies_detect_sp60,
    .hash_work       = hash_driver_work,
    .scanwork        = spond_scanhash_sp60,
    .flush_work      = spond_flush_work_sp60, // TODO: other drivers using same function as update_work
    .update_work     = spondoolies_update_work_sp60,
};
