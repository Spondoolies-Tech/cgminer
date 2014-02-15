/*
	This file holds functions needed for minergate packet parsing/creation
	by Zvisha Shteingart
*/

#include "mg_proto_parser.h"
#include "assert.h"
//#include "spond_debug.h"




minergate_req_packet *allocate_minergate_packet_req(
											uint8_t requester_id, 
											uint8_t request_id) {
	minergate_req_packet *p  = (minergate_req_packet*)malloc(sizeof(minergate_req_packet));
	p->requester_id = requester_id;
	p->req_count = 0;
	p->protocol_version = MINERGATE_PROTOCOL_VERSION;
	p->request_id = request_id;
	p->magic = 0xcafe;
	p->resrved1 = 0;
	return p;
}


minergate_rsp_packet *allocate_minergate_packet_rsp(
											uint8_t requester_id, 
											uint8_t request_id) {
	
	minergate_rsp_packet *p  = (minergate_rsp_packet*)malloc(sizeof(minergate_rsp_packet));
	p->requester_id = requester_id;
	p->rsp_count = 0;
	p->protocol_version = MINERGATE_PROTOCOL_VERSION;
	p->request_id = request_id;
	p->magic = 0xcafe;
	p->resrved1 = 0;
	return p;
}



