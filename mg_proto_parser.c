/*
	This file holds functions needed for minergate packet parsing/creation
	by Zvisha Shteingart
*/

#include "mg_proto_parser.h"
#include "assert.h"
//#include "spond_debug.h"
#ifndef passert
#define passert assert
#endif

void parse_minergate_packet(minergate_packet *mp, minergate_data_handler minergate_data_processor, void* context,void* context2) {

	uint16_t current_ptr  = 0;
	passert(mp->protocol_version == MINERGATE_PROTOCOL_VERSION);
	//printf("4.1\n");

	while (current_ptr < mp->data_length) {
		//printf("4.2\n");
		minergate_data* md = (minergate_data*)(mp->data+current_ptr);
		//printf("4.3\n");
		//printf("-- %d:%x\n", current_ptr, md->magic);
		passert(md->magic == 0xA5);
		(*minergate_data_processor)(md, context, context2);
		current_ptr += md->data_length + MINERGATE_DATA_HEADER_SIZE;
	}

}




minergate_packet *allocate_minergate_packet(int data_length, 
											uint8_t requester_id, 
											uint8_t request_id) {
	passert(data_length < 0xFFFF + MINERGATE_PACKET_HEADER_SIZE);
	minergate_packet *p  = (minergate_packet*)malloc(data_length + MINERGATE_PACKET_HEADER_SIZE);
    p->max_data_length = data_length;
	p->requester_id = requester_id;
	p->data_length = 0;
	p->protocol_version = MINERGATE_PROTOCOL_VERSION;
	p->request_id = request_id;
	p->magic = 0xcafe;
	p->resrved1 = 0;
	return p;
}



minergate_data* get_minergate_data(minergate_packet *mp, uint16_t data_length, uint8_t data_id) {
	minergate_data* md = (minergate_data*)(&mp->data + mp->data_length);
	md->data_length = data_length;
	md->data_id = data_id;
	md->magic = 0xa5;
	mp->data_length += data_length + MINERGATE_DATA_HEADER_SIZE;
    passert(mp->data_length <= mp->max_data_length);
	return md;
}

