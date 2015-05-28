/*
 * Copyright 2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2014 Zvi (Zvisha) Shteingart - Spondoolies-tech.com
 * Copyright 2014 Dmitry (Dima) Kuzminov - Spondoolies-tech.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 *
 * Note that changing this SW will void your miners guaranty
 */
#ifndef __MG_PROTO_PARSER_V3_H__
#define __MG_PROTO_PARSER_V3_H__

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <netinet/in.h>

#ifndef passert
#define passert assert
#endif

#define pxgate_PROTOCOL_VERSION_MINOR 1
#define pxgate_PROTOCOL_VERSION_MAJOR 6
#define pxgate_PROTOCOL_VERSION       ((pxgate_PROTOCOL_VERSION_MAJOR<<8)|(pxgate_PROTOCOL_VERSION_MINOR))

#define pxgate_SOCKET_FILE "/tmp/connection_pipe"

typedef enum {
    pxgate_MESSAGE_TYPE_CONNECT      = 0xCAFE1111,
    pxgate_MESSAGE_TYPE_JOB_REQ      = 0xCAFE2222,
    pxgate_MESSAGE_TYPE_JOB_REQ_REJ  = 0xCAFE3333,
    pxgate_MESSAGE_TYPE_JOB_REQ_ACK  = 0xCAFE4444,
    pxgate_MESSAGE_TYPE_RSP_REQ      = 0xCAFE5555,
    pxgate_MESSAGE_TYPE_RSP_NODATA   = 0xCAFE6666,
    pxgate_MESSAGE_TYPE_RSP_DATA     = 0xCAFE7777,
    pxgate_MESSAGE_TYPE_STALE_JOB    = 0xCAFE8888,
    pxgate_MESSAGE_TYPE_PUSH_JOBPACK_REQ  = 0xCAFE9999,
    pxgate_MESSAGE_TYPE_PUSH_JOBPACK_RSP  = 0xCAFEAAAA    
    
} pxgate_MESSAGE_TYPE;

#define SPOND_MAX_COINBASE_LEN      1024
#define SPOND_MAX_MERKLE_LEN        1024
#define SPOND_MAX_MERKLES           (SPOND_MAX_MERKLE_LEN>>5) // each merkle is 32 bytes
#define SPOND_MAX_NONCE2_SETSIZE    32

#define JOBPACK_SIZE            2
#define MIDSTATE_STATES         8


typedef struct {
    uint32_t work_id_in_sw; //? not sure we need it
    uint32_t difficulty;
    uint32_t timestamp;
    uint8_t  leading_zeroes;
    uint8_t  ntime_limit; //? not sure we need it
    uint8_t  ntime_offset; //? not sure we need it
    uint8_t  resr1;
    uint32_t coinbase_len; // in bytes
    uint8_t  coinbase[SPOND_MAX_COINBASE_LEN];
    uint32_t nonce2_offset;
    uint32_t merkles; // in 32 byte (256 bit)
    uint8_t  merkle[SPOND_MAX_MERKLE_LEN];
    uint8_t  header_bin[128]; // TODO: we clone data on pool header
    // it is duplicating data with difficulty
    // timestamp
} pxgate_do_mrkljob_req;



typedef struct {
   uint32_t    work_id_in_sw;
   uint32_t    work_id_in_hw;   
   uint32_t    difficulty;
   uint32_t    timestamp;
   uint32_t    mrkle_root;
   uint32_t    midstate[JOBPACK_SIZE][MIDSTATE_STATES];
   uint64_t    nonce2_jp_win[JOBPACK_SIZE]; // enonce
   uint8_t     nonce2_jp_len[JOBPACK_SIZE];
   uint32_t    mrkl_jp_root[JOBPACK_SIZE];   
   uint32_t    leading_zeroes_value;
   uint32_t    leading_zeroes_reg;   
   uint8_t     ntime_limit;
   uint8_t     resr2;
   uint8_t     nmidstates;
   uint8_t     resr1;
   uint32_t    winner_nonce;
} pxgate_jobpack_req;



#define MAX_REQUESTS 1
#define MAX_JOBPACK_REQUESTS 100

#define MAX_RESPONDS 100

typedef struct {
    uint32_t work_id_in_sw;
    uint32_t mrkle_root;     // to validate
    uint32_t winner_nonce;
    uint8_t  nonce2_len;
    uint64_t nonce2;        // winner enonce as well
    //uint8_t  chip_id;
    uint8_t  ntime_offset;
    uint8_t  res;            // 0 = done, 1 = overflow, 2 = dropped bist
    uint8_t  resrv1;
    uint8_t  resrv2;
} pxgate_do_job_rsp;

typedef struct {
    uint32_t                message_type;
    uint32_t                message_size;
    uint16_t                protocol_version;
} pxgate_packet_header;

typedef struct {
    pxgate_packet_header header;
    uint16_t                protocol_version;
    uint8_t                 mask; // 0x01 = first request, 0x2 = drop old work
    pxgate_do_mrkljob_req    req; // array of requests
} pxgate_req_packet;

typedef struct {
    pxgate_packet_header header;
    uint8_t                 gh_div_10_rate; // == 
    uint16_t                rsp_count;
    pxgate_do_job_rsp    rsp[MAX_RESPONDS]; // array of responce
} pxgate_rsp_packet;

typedef struct {
    pxgate_packet_header header;
    uint32_t                 rsv[4];
} pxgate_gen_packet;


typedef struct {
    pxgate_packet_header   header;
    uint16_t                  protocol_version;
    uint8_t                   mask; // 0x01 = first request, 0x2 = drop old work
    uint16_t                  req_count;
    pxgate_jobpack_req     req[MAX_JOBPACK_REQUESTS]; // array of requests
} pxgate_req_jobpack_packet;


int     do_read(int fd, void *buf, int len);
int     do_write(int fd, const void *buf, int len);
int     do_read_packet(int fd, void* buf, int len);
#endif //__MG_PROTO_PARSER_V3_H__
