/***************************************************************************
 *            ping.h
 *
 *  Copyright  2012  guofeng
 *  <guofeng1208@163.com>
 ****************************************************************************/
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301,  USA
 */


#ifndef PING_H
#define PING_H


#include "defines.h"

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>




/*
 * define flags
 * use a unsigned 32-bit param
 */
#define F_ADAPTIVE  0x0001  /* Adaptive ping */
#define F_BROADCAST 0x0002  /* Allow pinging a broadcast address */
#define F_BIND      0x0004  /* No changing source address of probes */
#define F_INTERVAL  0x0008  /* Interval between send each packet */
#define F_FLOOD     0x0010  /* Flood ping */
#define F_SOURCERT  0x0020  /* Special source route */
#define F_ENDLINE   0x0040  /* Special endline */
#define F_IF_ADDR   0x0080  /* Set outgoing to specified interface address */
#define F_NUMERIC   0x0200  /* Numeric output only */
#define F_QUITE     0x0400  /* Quiet output */
#define F_RECORDRT  0x0800  /* Record route */
#define F_BYPASSRT  0x1000  /* Bypass the normal routing tables */
#define F_TIMEOUT   0x2000  /* Time to wait for a response, in seconds */



/* simulate lost packet */
//#define DEBUG_LOST

/* if use the IPv6 IPV6_STICKY option */
#define IPV6_STICKY 1

/* icmp packet max size */
#define MAX_DATA_LEN    65507   /* 65535 - 20 - 8 */

/* flood ping interval in ms */
#define FLOOD_INTERVAL  100

/* min interval normal user can sepcial in ms */
#define MIN_USR_INTERVAL    200

/* default flood ping interval, in ms */
#define DFL_FLOOD_INTERVAL  10



void    init_v4( int , char ** );
void    init_v6( int , char ** );

int     proc_v4( char *, ssize_t, struct msghdr *, struct timeval * );
int     proc_v6( char *, ssize_t, struct msghdr *, struct timeval * );

int     proc_err_v4( const struct msghdr *, int , struct icmp *, int );
int     proc_err_v6( const struct msghdr *, int , struct icmp6_hdr *, int );

void    pr_source_rt_v4( const __u8 *, int );
void    pr_source_rt_v6( struct cmsghdr * );

void    send_icmp();
void    send_v4();
void    send_v6();


void    pr_banner();
void    show_status();
void    show_result();
__u16   in_cksum( const __u16 *addr, int );

void    show_reply( int , int ,
                    const struct msghdr *, int ,
                    __u16 , int ,
                    const struct timeval * );



struct  proto
{
    int     ( *proc )( char *, ssize_t, struct msghdr *, struct timeval * );
    void    ( *send )();
    void    ( *init )( int , char ** );

    struct  sockaddr *sa_peer;
    struct  sockaddr *sa_from;
    struct  sockaddr *sa_local;

    socklen_t   sa_len;

    int icmp_proto;

};




#endif // PING_H
