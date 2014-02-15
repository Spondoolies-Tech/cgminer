#ifndef ____MINERGATE_LIB_H___
#define ____MINERGATE_LIB_H___

//#include "squid.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <netinet/in.h>
//#include "queue.h"
//#include "spond_debug.h"




#define MINERGATE_PROTOCOL_VERSION 1
#define MINERGATE_SOCKET_FILE "./connection_pipe"


typedef enum {
	//MINERGATE_DATA_ID_CONNECT = 1,
	MINERGATE_DATA_ID_DO_JOB_REQ = 2,
	MINERGATE_DATA_ID_DO_JOB_RSP = 3, 

} MINERGATE_DATA_ID;

#define MINERGATE_DATA_HEADER_SIZE 4
typedef struct { 
	uint8_t data_id;
	uint8_t magic; // 0xa5
	uint16_t data_length;
	uint8_t data[1]; // array of requests
} minergate_data;


#define MINERGATE_PACKET_HEADER_SIZE 8
typedef struct {
	uint8_t requester_id;
	uint8_t request_id;
	uint8_t protocol_version;
	uint8_t resrved1; // == 
	uint16_t data_length;
    uint16_t max_data_length; // not used in protocol, just for sw. Yes, it's bad but I am lazy.
	uint16_t magic; // 0xcafe
	uint8_t data[1]; // array of requests
} minergate_packet;


typedef struct {
	int nada;
} minergate_connect;



typedef struct {
	uint32_t work_id_in_sw;
	uint32_t difficulty;
	uint32_t timestamp;
	uint32_t mrkle_root;
	uint32_t midstate[8];
    uint8_t leading_zeroes;
    uint8_t res1;
    uint8_t res2;
    uint8_t res3;        
} minergate_do_job_req;




typedef struct {
	uint32_t work_id_in_sw;
	uint32_t mrkle_root;     // to validate
	uint32_t winner_nonce;
    uint8_t  res;            // 0 = done, 1 = overflow, 2 = dropped bist
} minergate_do_job_rsp;




/*
typedef struct _JOB_RESPONCE_MINERGATE_CLIENT {
	SLIST_ENTRY(_JOB_RESPONCE_QUEUE_FOR_MINERGATE_CLIENT) next;
	minergate_do_job_rsp rsp;
} JOB_RESPONCE_MINERGATE_CLIENT;
SLIST_HEAD(JOB_RESPONCE_HEAD, _JOB_RESPONCE_MINERGATE_CLIENT);
*/



typedef int (*minergate_data_handler)(minergate_data* md, void * context, void * context2);

void parse_minergate_packet(minergate_packet *mp, minergate_data_handler mdh, void* c, void*c2);
minergate_packet *allocate_minergate_packet(int data_length, 
											uint8_t requester_id, 
											uint8_t request_id);
minergate_data* get_minergate_data(minergate_packet *mp, uint16_t length, uint8_t data_id);




#define MINERGATE_TOTAL_QUEUE 100

#endif
