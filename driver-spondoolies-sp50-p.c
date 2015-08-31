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

/*
 This file holds functions needed for minergate packet parsing/creation
   by Zvisha Shteingart
*/
#include <errno.h>
#include <unistd.h>

//#include "miner.h"
#include "driver-spondoolies-sp50-p.h"
#include "assert.h"

int do_read(int fd, void *buf, int len) {
    uint8_t *pos = (uint8_t*) buf;
    int left = len;
    while (left) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        int res;
        if ((res = select(fd + 1, &set, NULL, NULL, NULL)) < 0) {
            /*
            applog(LOG_ERR, "%s:%d: select failed fd=%d error=%s(%d)",
                    __FUNCTION__,
                    __LINE__,
                    fd,
                    strerror(errno),
                    errno);
                    */
            return res;
        }
        if ((res = read(fd, pos, left)) < 0) {
            /*
            applog(LOG_ERR, "%s:%d: read failed fd=%d error=%s(%d)",
                    __FUNCTION__,
                    __LINE__,
                    fd,
                    strerror(errno),
                    errno);
                    */
            return res;
        } else if (res == 0) {
        /*
            applog(LOG_ERR, "%s:%d: fd=%d Connection Closed, quietly exiting...",
                    __FUNCTION__,
                    __LINE__,
                    fd);
                    */
            return len - left;
        }
        left -= res;
        pos += res;
    }
    return len;
}

int do_read_packet(int fd, void* buf, int len)
{
    pxgate_packet_header* header = (pxgate_packet_header*) buf;
    if (do_read(fd, header, sizeof(pxgate_packet_header)) != sizeof(pxgate_packet_header)) {
        /*
        applog(LOG_ERR, "%s:%d: fd=%d do_read header failed",
                __FUNCTION__,
                __LINE__,
                fd);
                */
        return 0;
    }
    if (header->message_size+sizeof(pxgate_packet_header) > len) {
        /*
        applog(LOG_ERR, "%s:%d: fd=%d buf is too small or message header data is bad",
                __FUNCTION__,
                __LINE__,
                fd);
                */
        return 0;
    }
    int res = do_read(fd, (uint8_t*)buf+sizeof(pxgate_packet_header), header->message_size);
    return res > 0 ? (res + sizeof(pxgate_packet_header)) : res;
}

int do_write(int fd, const void *buf, int len)
{
    uint8_t *pos = (uint8_t*) buf;
    int left = len;
    while (left) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        int res;
        if ((res = select(fd + 1, NULL, &set, NULL, NULL)) < 0) {
            /*
            applog(LOG_ERR, "%s:%d: select failed fd=%d error=%s(%d)",
                    __FUNCTION__,
                    __LINE__,
                    fd,
                    strerror(errno),
                    errno);
                    */
            return res;
        }
        if ((res = write(fd, pos, left)) < 0) {
            /*
            applog(LOG_ERR, "%s:%d: write failed fd=%d error=%s(%d)",
                    __FUNCTION__,
                    __LINE__,
                    fd,
                    strerror(errno),
                    errno);
                    */
            return res;
        }
        left -= res;
        pos += res;
    }
    return len;
}
