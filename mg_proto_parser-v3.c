/*
 * Copyright 2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2014 Zvi (Zvisha) Shteingart - Spondoolies-tech.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 *
 * Note that changing this SW will void your miners guaranty
 */

/*
	This file holds functions needed for minergate packet parsing/creation
	by Zvisha Shteingart
*/

#include <errno.h>

#include "mg_proto_parser-v3.h"
#include "assert.h"
//#include "spond_debug.h"

minergate_req_packet *allocate_minergate_packet_req_v3(uint8_t requester_id, uint8_t request_id)
{
	minergate_req_packet *p  = (minergate_req_packet*)malloc(sizeof(minergate_req_packet));
	p->requester_id = requester_id;
	p->req_count = 0;
	p->protocol_version = MINERGATE_PROTOCOL_VERSION;
	p->request_id = request_id;
	p->magic = 0xcaf4;
	p->mask |= 0x01; // first packet
	return p;
}

minergate_rsp_packet *allocate_minergate_packet_rsp_v3(uint8_t requester_id, uint8_t request_id)
{
	minergate_rsp_packet *p  = (minergate_rsp_packet*)malloc(sizeof(minergate_rsp_packet));
	p->requester_id = requester_id;
	p->rsp_count = 0;
	p->protocol_version = MINERGATE_PROTOCOL_VERSION;
	p->request_id = request_id;
	p->magic = 0xcaf4;
	p->gh_div_10_rate = 0;
	return p;
}

int do_read(int s, void *p, int len)
{
	void *p1 = p;
	int left = len;
	while (left) {
		fd_set set;
		FD_ZERO(&set);
		FD_SET(s, &set);

		int n;
		if ((n = select(s + 1, &set, NULL, NULL, NULL)) < 0) {
			fprintf(stderr, "%s, %d socket_fd=%d nread=%d nbytes=%d error=%s(%d)\n", __FUNCTION__, __LINE__, s, len - left, left, strerror(errno), errno);
			return n;
		}

		if ((n = read(s, p1, left)) < 0) {
			fprintf(stderr, "%s, %d socket_fd=%d nread=%d nbytes=%d error=%s(%d)\n", __FUNCTION__, __LINE__, s, len - left, left, strerror(errno), errno);
			return n;
		}

		if (!n) {
			fprintf(stderr, "%s, %d socket_fd=%d Connection Closed, quietly exiting...\n", __FUNCTION__, __LINE__, s, n);
			return len - left;
		}

		left -= n;
		p1 = (void *)((unsigned char *)p + n);
	}
	return len;
}

int do_write(int s, const void *p, int len)
{
	const void *p1 = p;
	int left = len;
	while (left) {
		fd_set set;
		FD_ZERO(&set);
		FD_SET(s, &set);

		int n;
		if ((n = select(s + 1, NULL, &set, NULL, NULL)) < 0) {
			fprintf(stderr, "%s, %d socket_fd=%d nwrote=%d nbytes=%d error=%s(%d)\n", __FUNCTION__, __LINE__, s, len - left, left, strerror(errno), errno);
			return n;
		}

		if ((n = write(s, p1, left)) < 0) {
			fprintf(stderr, "%s, %d socket_fd=%d nwrote=%d nbytes=%d error=%s(%d)\n", __FUNCTION__, __LINE__, s, len - left, left, strerror(errno), errno);
			return n;
		}

		left -= n;
		p1 = (void *)((unsigned char *)p + n);
	}
	return len;
}
