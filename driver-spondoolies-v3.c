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

static char *print_binary(unsigned char *data, int len, char *print_area)
{
	char *p = print_area;
	int n;
	for (n = 0; n < len; ++n) {
		sprintf(p, "%02x", data[n]);
		p += 2;
		if (((n + 1) % 4) == 0 && n != len - 1) {
			sprintf(p++, "-");
		}
	}
	return print_area;
}

static char *print_binary_flip(unsigned char *dataIn, int lenIn, char *print_area)
{
	int len = ((lenIn - 1) / 4 + 1) * 4;
	uint8_t data[len];
	memset(data, 0, len);
	memcpy(data, dataIn, lenIn);
	uint32_t *d = (uint32_t*)data;
	int i, n;
	for (i = 0; i < len / 4; ++i) {
		d[i] = htonl(d[i]);
	}

	char *p = print_area;
	for (n = 0; n < len; ++n) {
		sprintf(p, "%02x", data[n]);
		p += 2;
		if (((n + 1) % 4) == 0 && n != len - 1) {
			sprintf(p++, "-");
		}
	}
	return print_area;
}

static inline void swap32yes(void *out, const void *in, size_t sz)
{
	size_t swapcounter;

	for (swapcounter = 0; swapcounter < sz; ++swapcounter)
		(((uint32_t*)out)[swapcounter]) = swab32(((uint32_t*)in)[swapcounter]);
}

extern void submit_nonce2_nonce(struct thr_info *thr, uint32_t pool_no, uint64_t nonce2, uint32_t nonce);

static char* print_hex(char* dst, int size_of_dist, void* src, int size_of_src) {
    char *pos = dst;
    uint8_t* src_bytes = (uint8_t*) src;
    int elements = size_of_src < (size_of_dist/3) ? size_of_src : (size_of_dist/3);
    int i;
    for (i = 0; i < elements; ++i) {
        sprintf(pos, "%02x:", src_bytes[i]);
        pos += 3;
    }
    return dst;
}

static int spond_get_free_job_container_id(struct spond_adapter *device)
{
    int i = 0;
    for ( ; i < MAX_JOBS_IN_MINERGATE; i++) {
        if (device->my_jobs[i].cgminer_work == NULL) {
            return i;
        }
    }
    return -1;
}

static struct work* spond_get_work__by_job_id(struct spond_adapter *device, int my_job_id)
{
    return device->my_jobs[my_job_id].cgminer_work;
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
#ifdef WORDS_BIGENDIAN
    quit(1, "Odnako WORDS_BIGENDIAN");
#endif
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

static void fill_minergate_request(minergate_do_job_req* job, struct thr_info *thr, int my_job_id)
{
    int i;
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    struct pool *pool = device->my_jobs[my_job_id].cgminer_work->pool;
    uint64_t difficulty_64bit = round(pool->sdiff);
    /*
     * fill the job
     */
    memset(job, 0, sizeof(minergate_do_job_req));
    job->work_id_in_sw = my_job_id;
    uint8_t bytes[8]; // ntime 32 bit, nbits 32 bit  
    memcpy(
            bytes,
            pool->header_bin + 4 /*bbversion*/ + 32 /*prev_hash*/ + 32 /*blank_merkle*/,
            4 /*ntime*/ + 4 /*nbits*/
            );
	LOCAL_swap32le(uint8_t, bytes, 2)
	uint32_t converted[2];
	swap32yes(converted, bytes, 2);
	job->timestamp  = ntohl(converted[0]);
	job->difficulty = ntohl(converted[1]);
    job->mrkle_root = 0; // TODO: looks like wrong place for this variable
    memcpy(job->header_bin, pool->header_bin, sizeof(job->header_bin));
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
	for (i = 0; i < pool->merkles; ++i) {
		memcpy(job->merkle + 32 * i, pool->swork.merkle_bin[i], 32);
	}
#if 1 //TODO: remove me
    {
        char p[1024];
        for (i = 0; i < job->merkles; ++i) {
            printf("%s, %d:### merkle-bin=%s\n", __FUNCTION__, __LINE__, print_binary(job->merkle + i * 32, 32, p));
        }
    }
#endif
    // TODO: please remove me
    applog(LOG_ERR, "%s %s work_id_in_sw[0x%x] difficulty[0x%x] timestamp[0x%x] leading_zeros[%d] mrkle_root[0x%08x]",
            spondooliesv3_drv.dname,
            __FUNCTION__,
            job->work_id_in_sw,
            job->difficulty,
            job->timestamp,
            job->leading_zeroes,
            job->mrkle_root
          );
    applog(LOG_ERR, "%s %s coinbase_len[%d] nonce2_offset[0x%x] merkles[%d] n2size[%d]",
            spondooliesv3_drv.dname,
            __FUNCTION__,
            job->coinbase_len,
            job->nonce2_offset,
            job->merkles,
            pool->n2size
          );
    char buffer[4096];
    printf("pool->header_bin[%s]",
            print_hex(buffer, sizeof(buffer), pool->header_bin, sizeof(pool->header_bin))
          );
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
                // TODO: what to do with:
                //       rsp->requester_id
                //       rsp->request_id
                //       rsp->gh_div_10_rate
                int results = rsp->rsp_count;
                for (i = 0; i < results; ++i) {
#if 1
                    // calculate midstate if win
                    static char p[2048];
                    struct work *work = spond_get_work__by_job_id(device, rsp->rsp[i].work_id_in_sw);

                    uint8_t coinbase[work->coinbase_len];
                    memcpy(coinbase, work->coinbase, work->coinbase_len);
                    *(uint64_t *)(coinbase + work->nonce2_offset) = htole64((rsp->rsp[i].enonce[0])|((uint64_t)rsp->rsp[i].chip_id<<32));
                    printf("%s, %d: coinbase=%s\n", __FUNCTION__, __LINE__, print_binary(coinbase, work->coinbase_len, p));
                    work->nonce2 = htole64((rsp->rsp[i].enonce[0])|((uint64_t)rsp->rsp[i].chip_id<<32));

                    uint8_t merkle_root[32];
                    gen_hash(coinbase, merkle_root, work->coinbase_len);
                    printf("%s, %d: coinbase=%s\n", __FUNCTION__, __LINE__, print_binary(coinbase, work->coinbase_len, p));

                    uint8_t merkle_sha[64];
                    for (j = 0; j < work->merkles; ++j) {
                        memcpy(merkle_sha, merkle_root, 32);
                        memcpy(merkle_sha + 32, work->merklebin + j * 32, 32);
                        gen_hash(merkle_sha, merkle_root, 64);
                        printf("%s, %d: merkle-bin=%s\n", __FUNCTION__, __LINE__, print_binary(work->merklebin + j * 32, 32, p));
                        printf("%s, %d: merkle_root=%s\n", __FUNCTION__, __LINE__, print_binary_flip(merkle_root, 32, p + 1024));
                    }
                    uint8_t merkle_root_swapped[32];
                    flip32(merkle_root_swapped, merkle_root);
                    memcpy(work->data + 36, merkle_root_swapped, 32);
                    printf("%s, %d: merkle_root=%s\n", __FUNCTION__, __LINE__, print_binary(merkle_root, 32, p));
                    printf("%s, %d: merkle_root_swapped=%s\n", __FUNCTION__, __LINE__, print_binary(merkle_root_swapped, 32, p));
                    printf("%s, %d: work_data=%s\n", __FUNCTION__, __LINE__, print_binary(work->data, 128, p));

                    calc_midstate(work);

                    printf("%s, %d: midstate=%s\n", __FUNCTION__, __LINE__, print_binary(work->midstate, 32, p));
                    LOCAL_swap32le(unsigned char, work->midstate, 32/4);
                    printf("%s, %d: midstate=%s\n", __FUNCTION__, __LINE__, print_binary(work->midstate, 32, p));
#endif
#if 1
                    printf("#####################################################################################\n");
                    printf("#####################################################################################\n");
                    printf("#####################################################################################\n");
                    printf("%s, %d: winner_nonce=%08x\n", __FUNCTION__, __LINE__, rsp->rsp[i].winner_nonce[0]);
					submit_nonce(
                            work->thr,
                            work,
                            ntohl(rsp->rsp[i].winner_nonce[0])
                            );
                    //quit(1, "ooof");
                    printf("#####################################################################################\n");
                    printf("#####################################################################################\n");
                    printf("#####################################################################################\n");
#else
                    submit_nonce2_nonce(
                            thr,
                            rsp->rsp[i].work_id_in_sw           /*pool_no*/,
                            rsp->rsp[i].enonce[0]               /*nonce2*/,
                            rsp->rsp[i].winner_nonce[0]         /*nonce*/);
                    submit_nonce2_nonce(
                            thr,
                            rsp->rsp[i].work_id_in_sw           /*pool_no*/,
                            ntohl(rsp->rsp[i].enonce[0])               /*nonce2*/,
                            rsp->rsp[i].winner_nonce[0]         /*nonce*/);
                    submit_nonce2_nonce(
                            thr,
                            rsp->rsp[i].work_id_in_sw           /*pool_no*/,
                            rsp->rsp[i].enonce[0]               /*nonce2*/,
                            ntohl(rsp->rsp[i].winner_nonce[0])         /*nonce*/);
                    submit_nonce2_nonce(
                            thr,
                            rsp->rsp[i].work_id_in_sw           /*pool_no*/,
                            ntohl(rsp->rsp[i].enonce[0])               /*nonce2*/,
                            ntohl(rsp->rsp[i].winner_nonce[0])         /*nonce*/);
                    quit(1, "ooof");
#endif
                    char buffer[1024];
                    applog(LOG_ERR, "%s: win [%d/%d] pool_no [%08x] enonce_orig[%s] enonce[%08x] nonce [%08x]",
                            spondooliesv3_drv.dname,
                            i,
                            results,
                            rsp->rsp[i].work_id_in_sw           /*pool_no*/,
                            print_hex(buffer, sizeof(buffer), rsp->rsp[i].enonce, sizeof(rsp->rsp[i].enonce)),
                            rsp->rsp[i].enonce                  /*nonce2*/,
                            rsp->rsp[i].winner_nonce[0]         /*nonce*/);
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
    struct cgpu_info *spondoolies = thr->cgpu;
    struct spond_adapter *device = spondoolies->device_data;
    struct pool *pool = NULL;//current_pool();
    struct work *work = NULL;
    if (thr->work_restart || thr->work_update) {
        int id = -1;
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
        id = spond_get_free_job_container_id(device);
        if (id <0) {
            applog(LOG_ERR, "%s: no free container to handle the job", spondooliesv3_drv.dname);
            return 0;
        }
        work = get_work(thr, thr->id);
#if 1 // TODO: do we need it, checked for crash..??
        work->thr = spondoolies->thr[0];
        work->thr_id = spondoolies->thr[0]->id;
        assert(work->thr);
        work->subid = 0;
#endif
        pool = work->pool;
        device->my_jobs[id].cgminer_work = work;
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
        static char p[2048];
        printf("%s, %d: coinbase=%s\n", __FUNCTION__, __LINE__, print_binary(pool->coinbase, pool->coinbase_len, p));
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
		cg_wlock(&pool->data_lock);
        fill_minergate_request(&req_packet.req[0], thr, id);
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
    return polling_and_return_number_of_wins(thr);
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
