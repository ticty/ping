/***************************************************************************
 *            ping.c
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

#include "defines.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>


#include "misc.h"
#include "ping.h"


static void main_loop();

static void init( int , char ** );
static void init_common();
static void init_signal();

static void quit( __u16 );
static void exit_handler();
static void sig_handler( int );

static int  check_send_interval();
static void updata_endline();

struct addrinfo *host_addr( const char *, int, int, int );
int addr_ntop( const void *, char *, int , char *, int , int );

static void update_tv_data( const struct timeval * );

static void version();
static void usage();


/* icmp protocol instance */
static struct  proto *pr;


/* the length we use in icmp */
#define ICMPHDR_LEN ( (pr->icmp_proto == IPPROTO_ICMP) ? \
                      8 : \
                      (int)sizeof( struct icmp6_hdr ) \
                    )


/* the length of ip header */
#define IPHDR_LEN   ( (pr->icmp_proto == IPPROTO_ICMP) ? \
                      (int)sizeof( struct ip ) : \
                      (int)sizeof( struct ip6_hdr ) \
                    )


/* icmp4 */
static struct  proto proto_v4 = {
    proc_v4,
    send_v4,
    init_v4,
    NULL,
    NULL,
    NULL,
    0,
    IPPROTO_ICMP
};

/* icmp6 */
static struct  proto proto_v6 = {
    proc_v6,
    send_v6,
    init_v6,
    NULL,
    NULL,
    NULL,
    0,
    IPPROTO_ICMPV6
};


/* be careful here */
#define MAX_ICMP4_ERR_TYPE    ICMP_TIMXCEED
#define MAX_ICMP4_ERR_CODE    ICMP_UNREACH_PRECEDENCE_CUTOFF

#define MAX_ICMP6_ERR_TYPE    ICMP6_PARAM_PROB
#define MAX_ICMP6_ERR_CODE    ICMP6_DST_UNREACH_NOPORT


#ifdef _ISOC99_SOURCE /* compiled under C99 */
const char *icmp4_err[][MAX_ICMP4_ERR_CODE + 1] = {
    [ICMP_UNREACH] = { "Net Unreachable", "Host Unreachable", \
                       "Protocol Unreachable", "Port Unreachable", \
                       "Fragmentation Error", "Source Route Failed", \
                       "Unknown Net", "Unknown Host", "Src Host Isolated", \
                       "Net Denied", "Host Denied", "Bad Tos for Net", \
                       "Bad Tos for Host", "Admin Prohib", \
                       "Host Prec Vio", "Prec Cutoff" },
    [ICMP_SOURCEQUENCH] = { "Source Quench" },
    [ICMP_TIMXCEED] = { "TTL Exceeded", "fragment Timeout" },
};

const char *icmp6_err[][MAX_ICMP4_ERR_CODE + 1] = {
    [ICMP6_DST_UNREACH] = { "No Route", "Admin Prohib", \
                            "Beyond scope of source address", \
                            "Addr Unreachable", "Bad Port" },
    [ICMP6_PACKET_TOO_BIG] = { "Packet Too Big" },
    [ICMP6_TIME_EXCEEDED] = { "Hop Limit == 0 Transit", "Reassembly Timeout" },
    [ICMP6_PARAM_PROB] = { "Erroneous Header Field", \
                           "Unrecognized Next Header", \
                           "Unrecognized IPv6 Option" }
};
#else
const char *icmp4_err[][MAX_ICMP4_ERR_CODE+1] = {
    { NULL },   /* 0 */
    { NULL },   /* 1 */
    { NULL },   /* 2 */

    { "Net Unreachable", "Host Unreachable", "Protocol Unreachable", \
      "Port Unreachable", "Fragmentation Error", "Source Route Failed", \
      "Unknown Net", "Unknown Host", "Src Host Isolated", "Net Denied", \
      "Host Denied", "Bad Tos for Net", "Bad Tos for Host", "Admin Prohib", \
      "Host Prec Vio", "Prec Cutoff" }, /* 3 */
    { "Source Quench" },    /* 4 */

    { NULL },   /* 5 */
    { NULL },   /* 6 */
    { NULL },   /* 7 */
    { NULL },   /* 8 */
    { NULL },   /* 9 */
    { NULL },   /* 10 */
    { "TTL exceeded", \
      "fragment reassembly time exceeded" }   /* 11 -- ICMP_TIMXCEED */
};

const char *icmp6_err[][MAX_ICMP4_ERR_CODE + 1] = {
    { NULL },   /* 0 */
    { "No Route", "Admin Prohib", \
      "Beyond scope of source address", "Addr Unreachable", \
      "Bad Port" },         /* 1 */
    { "Packet Too Big" },   /* 2 */
    { "Hop Limit == 0 Transit", "Reassembly Timeout" }, /* 3 */
    { "Erroneous Header Field", "Unrecognized Next Header", \
      "Unrecognized IPv6 Option" }  /* 4 */
};
#endif  /* _ISOC99_SOURCE */



/* send buffer */
static char send_buf[MAX_DATA_LEN];


/* send socket buffer size
 * Todo:
 * current is not configurable to user ( 'r' 'R' is both used )
 */
static int s_sendbuf;


/* receive socket buffer size */
static int s_recvbuf;


/* ping flags */
static __u32   globle_flags;


/* icmp sockfd */
static int icmp_sockfd;


/* destination cannonname */
static char *canonname;


/* packet count to send */
static int mount;


/* Wait interval seconds between sending each packet */
static double interval;


/* interface name or outgoing ip address */
static char *interface;


/* preload count */
static int preload;


/* packet size */
static int datalen;


/* ip option length */
static int ip_optlen;


/* IP Time to Live */
static int ttl;


/* deadline */
static double deadline;


/* timeout */
static double timeout;


/* pid */
static pid_t pid;


/* if have enough size to contain time in icmp data */
static int contain_time;


/* send sequence */
static __u16 seqnum;

/* receive count */
static __u32 recvnum;

/* error count ( unreachable, prohibited, etc.) ) */
static __u32 errnum;

/* last received icmp sequence number */
static __u32 lr;


#define PACKET_STATE ( recvnum == seqnum ? \
                       PING_ALL : \
                       ( recvnum == 0 ) ? PING_NONE : PING_PART \
                     )


/* total received packet rtt time */
static struct timeval tv_total;

/* begin time */
static struct timeval tv_begin;

/* min rtt time */
static struct timeval tv_min;

/* max rtt time */
static struct timeval tv_max;

/* last send time */
static struct timeval tv_lsend;


#if ! IPV6_STICKY
/* IPv6 source route buf */
static char *v6_source_rt;

/* the IPv6 source route buf len */
static int v6_source_rt_len;

#endif  /* IPV6_STICKY */


/* the state of parse */
static int is_in_parse;

/* is pending send */
static int is_pending_send;

/* uid */
static __uid_t uid;




int main( int argc, char *argv[] )
{
    init( argc, argv );
    main_loop();

    return 0;
}



/* main loop */
void    main_loop()
{
    int res;
    ssize_t len;

    char recv_buf[MAX_DATA_LEN];
    char control_buf[MAX_DATA_LEN];

    struct msghdr msg;
    struct iovec iov;
    struct timeval tv;

    iov.iov_base = recv_buf;
    iov.iov_len = sizeof(recv_buf);

    msg.msg_name = pr->sa_from;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_control = control_buf;

    /* print the begin banner */
    pr_banner();

    /* set start time */
    gettimeofday( &tv_begin, NULL );

    /* send first packet */
    send_icmp();

    /*
     * start timer
     * there will always exist a timer during running.
     * if user not special a interval, normally it is set to 1000ms
     * if it is flood,
     * then the default set to 10ms for root and MIN_USR_INTERVAL for others
     * if it is adaptive ping, then default set to MIN_USR_INTERVAL
     * user can special the interval,
     * but only no less than MIN_USR_INTERVAL for normal permission
     */
    if( start_timer( interval ) != 0 )
    {
        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    for(;;)
    {
        msg.msg_namelen = pr->sa_len;
        msg.msg_controllen = sizeof(control_buf);

        len = recvmsg( icmp_sockfd, &msg, 0 );
        //printf( "recv %d byte\n", (int)len );

        if( len > 0 )
        {
#ifdef DEBUG_LOST
            if( lost_some( 5 ) == 1 )
            {
                msg_log( L_NOR,
                         "%s: skip one packet!\n",
                         __func__ );
                continue;
            }
#endif  /* DEBUG_LOST */

            gettimeofday( &tv, NULL );

            /* not to send during msg-parse */
            is_in_parse = 1;
            res = pr->proc( recv_buf, len, &msg, &tv );
            is_in_parse = 0;

            /* special count and had recv such mount reply */
            if( mount && (int)lr == mount - 1 )
            {
                if( globle_flags & F_ENDLINE && recvnum < seqnum )
                {
                    continue;
                }

                exit(EXIT_SUCCESS);
            }

            if( res != 0 )
            {
                continue;
            }

            /*
             * consider this scenario:
             * if recv a reply,
             * and cost much time in msg proc( DNS address resolv ),
             * since async signal-drivered send-func may had send many icmp
             * during this time,
             * and also stored many packet in the socket buffer,
             * which are waiting to be received.
             * then we call a recvmsg and get the head one in the socket buffer,
             * while parse the rtt of this packet,
             * we may find that the rtt contained
             * the time of the last msg parse time,
             * it is much unexpected bigger.
             *
             * I mainly have three ways to solve this:
             *      1. not use signal-drivered async send
             *      2. call recvmsg async and store timrstamp for each,
             *         maybe use thread or other technic
             *      3. pending signal-drivered async send
             *
             * I finnally choose the third way, and just use two variables
             * 'is_pending_send', 'is_in_parse' to control sending and parsing
             */
            if( is_pending_send == 1 )
            {
                /*
                 * if has an endline, then cale the past timer time,
                 * endline minus it
                 */
                if( globle_flags & F_ENDLINE )
                {
                    updata_endline();
                }

                send_icmp();
                is_pending_send = 0;
            }
            /* flood mode, send as soon as receive one , or clock expired */
            else if( globle_flags & F_FLOOD )
            {
                if( check_send_interval() != 0 )
                {
                    continue;
                }

                if( globle_flags & F_ENDLINE )
                {
                    updata_endline();
                }

                send_icmp();
            }
            /* send as soon as recv, or MIN_USR_INTERVAL came */
            else if( globle_flags & F_ADAPTIVE )
            {
                /*
                 * normal user has a limit of MIN_USR_INTERVAL,
                 * if the send interval littler than MIN_USR_INTERVAL, 
                 * then not send
                 */
                if( check_send_interval() != 0 )
                {
                    continue;
                }

                if( globle_flags & F_ENDLINE )
                {
                    updata_endline();
                }

                send_icmp();
            }

            continue;
        }

        if( len < 0 )
        {
            if( errno == EINTR )
            {
                /* signal interupt here */
                continue;
            }
            /* recv timeout */
            else if( errno == EAGAIN )
            {
                /* if set timeout, then try to send again if meet condition */
                if( globle_flags & F_TIMEOUT )
                {
                    /* reach user special packet count and timeout */
                    if( mount && seqnum >= mount )
                    {
                        exit(EXIT_SUCCESS);
                    }

                    /* check time since last send if need */
                    if( check_send_interval() != 0 )
                    {
                        continue;
                    }

                    if( globle_flags & F_ENDLINE )
                    {
                        updata_endline();
                    }

                    send_icmp();
                }

//                msg_log( L_ERR,
//                         "%s: recvmsg timeout\n",
//                         __func__);

                continue;
            }
        }

        /* len == 0 ??? */
    }

}




/*
 * initial globle variable default value
 * parse cmdline
 * choose a write icmp procotol based on destination address
 * call the icmp init func accord to icmp type
 * call common icmp init func
 * call signal init func
 */
void    init( int argc, char *argv[] )
{
    struct addrinfo *res;

    int opt;
    const char options[] = ":AbBc:fgi:hI:l:nqRrs:S:t:Vw:W:";

    pr = NULL;
    globle_flags = 0;
    icmp_sockfd = -1;
    canonname = NULL;
    s_recvbuf = 10*1024;
    s_sendbuf = 0;
    mount = 0;
    seqnum = 0;
    recvnum = 0;
    errnum = 0;
    interval = 1;
    interface = NULL;
    preload = 1;
    datalen = 56;
    ip_optlen = 0;
    ttl = 64;
    deadline = 0;
    timeout = 0;
    contain_time = 1;
    lr = -1;

    uid = getuid();

#if ! IPV6_STICKY
    v6_source_rt = NULL;
    v6_source_rt_len = 0;
#endif  /*IPV6_STICKY*/

    is_in_parse = 0;
    is_pending_send = 0;

    tv_total.tv_sec = 0;
    tv_total.tv_usec = 0;

    pid = getpid() & 0xffff;

#ifdef DEBUG_LOST
    srandom( (unsigned int) time(NULL) );
#endif

    if( atexit(exit_handler) != 0 )
    {
        msg_log( L_ERR,
                 "%s: regedit atexit handler fail, %s\n",
                 __func__,
                 strerror(errno));

    }

    for(;;)
    {
        opt = getopt( argc, argv, options );

        if( opt == -1 )
        {
            break;
        }

        switch( opt )
        {
        case 'A':
            {
                if( globle_flags & F_INTERVAL )
                {
                    msg_log( L_ERR,
                             "%s: only can set one of \
                             -A adaptive ping or -f flood ping\n",
                             __func__);

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                globle_flags |= F_ADAPTIVE;
            }
            break;

        case 'b':
            {
                globle_flags |= F_BROADCAST;
            }
            break;

        case 'B':
            {
                globle_flags |= F_BIND;
            }
            break;

        case 'c':
            {
                if( mount > 0 )
                {
                    msg_log( L_ERR,
                             "%s: could not set \"-%c\" option mulity times\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                mount = atoi(optarg);

                if( mount <= 0 )
                {
                    msg_log( L_ERR,
                             "%s: invaild argument for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }
            }
            break;

        case 'f':
            {
                if( globle_flags & F_ADAPTIVE )
                {
                    msg_log( L_ERR,
                             "%s: only can set one of \
                             -A adaptive ping or -f flood ping\n",
                             __func__);

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                if( globle_flags & F_RECORDRT )
                {
                    msg_log( L_ERR,
                             "%s: only can set one of \
                             -R record route of -f flood ping\n",
                             __func__);

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                globle_flags |= F_FLOOD;
            }
            break;

        case 'g':
            {
                /* check it later */
                globle_flags |= F_SOURCERT;
            }
            break;

        case 'h':
            {
                usage();

                quit( _EXIT_CALL | PACKET_STATE | ERR_NONE );
            }
            break;

        case 'i':
            {
                interval = atof(optarg);

                if( interval < EPSINON )
                {
                    msg_log( L_ERR,
                             "%s: invaild argument for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }
                else if( interval 
                         < (double) MIN_USR_INTERVAL / SEC2MSEC && uid != 0 )
                {
                    msg_log( L_ERR,
                             "%s: only super-user can set interval to \
                             less than 0.2 seconds\n",
                             __func__ );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                globle_flags |= F_INTERVAL;
            }
            break;

        case 'I':
            {
                if( interface != NULL )
                {
                    msg_log( L_ERR,
                             "%s: could not set \"-%c\" option mulity times\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                /* check it based on family type later */
                globle_flags |= F_IF_ADDR;
                interface = optarg;
            }
            break;

        case 'l':
            {
                preload = atoi(optarg);

                if( preload <= 0 )
                {
                    msg_log( L_ERR,
                             "%s: invaild argument for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }
            }
            break;

        case 'n':
            {
                globle_flags |= F_NUMERIC;
            }
            break;

        case 'q':
            {
                globle_flags |= F_QUITE;
            }
            break;

        case 'R':
            {
                if( globle_flags & F_FLOOD )
                {
                    msg_log( L_ERR,
                             "%s: only can set one of \
                             -R record route of -f flood ping\n",
                             __func__);

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                globle_flags |= F_RECORDRT;
            }
            break;

        case 'r':
            {
                globle_flags |= F_BYPASSRT;
            }
            break;

        case 's':
            {
                datalen = atoi(optarg);

                if( datalen < 0 || datalen > MAX_DATA_LEN )
                {
                    msg_log( L_ERR,
                             "%s: invaild argument for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }
            }
            break;

        case 'S':
            {
                s_sendbuf = atoi( optarg );

                if( s_sendbuf <= 0 )
                {
                    msg_log( L_ERR,
                             "%s: invaild value for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }
            }

        case 't':
            {
                ttl = atoi(optarg);

                if( ttl < 0 || ttl > 255 )
                {
                    msg_log( L_ERR,
                             "%s: invaild argument for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }
            }
            break;

        case 'V':
            {
                version();

                quit( _EXIT_CALL | PACKET_STATE | ERR_NONE );
            }
            break;

        case 'w':
            {
                if( deadline > EPSINON )
                {
                    msg_log( L_ERR,
                             "%s: could not set \"-%c\" option mulity times\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                deadline = atof(optarg);

                if( deadline < EPSINON )
                {
                    msg_log( L_ERR,
                             "%s: invaild argument for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                globle_flags |= F_ENDLINE;
            }
            break;

        case 'W':
            {
                if( timeout > EPSINON )
                {
                    msg_log( L_ERR,
                             "%s: could not set \"-%c\" option mulity times\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                timeout = atof(optarg);

                if( timeout < EPSINON )
                {
                    msg_log( L_ERR,
                             "%s: invaild argument for \"-%c\" option\n",
                             __func__,
                             opt );

                    quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }

                globle_flags |= F_TIMEOUT;
            }
            break;

        case ':':
            {
                msg_log( L_ERR,
                         "%s: \"%s\" option need a argument\n",
                         __func__,
                         argv[optind-1] );

                quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }
            break;

        case '?':
            {
                msg_log( L_ERR,
                         "%s: unknown option \"-%c\"\n",
                         __func__,
                         optopt );

                quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }
            break;

        default:
            {
                msg_log( L_ERR,
                         "%s: unknown option \"-%c\"\n",
                         __func__,
                         optopt );

                quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }
        }
    }

    if( optind == argc )
    {
        msg_log( L_ERR,
                 "%s: no hostname specialled\n",
                 __func__ );

        quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }
    else if( optind == argc - 1 )
    {
        if( globle_flags & F_SOURCERT )
        {
            msg_log( L_ERR,
                     "%s: giving -g but no source route or host specialled\n",
                     __func__ );

            quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }
    }
    else
    {
        if( ~globle_flags & F_SOURCERT )
        {
            msg_log( L_ERR,
                     "%s: could special mulity hostname, \
                     special source route please use \'-g\'\n",
                     __func__ );

            quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }
    }

    /* get destination address info */
    res = host_addr( argv[argc-1], AF_UNSPEC, SOCK_DGRAM, AI_CANONNAME );

    if( res == NULL )
    {
        quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    if( res->ai_family == AF_INET )
    {
        pr = &proto_v4;
    }
    else if( res->ai_family == AF_INET6 )
    {
        /*
         * a IPv4 mapped IPv6 address
         * (Question) in fact, I want to test it why
         * but, how to simulate a V4MAPPE addr ?
         */
        if( IN6_IS_ADDR_V4MAPPED( res->ai_addr ) )
        {
            msg_log( L_ERR,
                     "%s: cannot ping IPv4-mapped IPv6 address\n",
                     __func__ );

            quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }

        pr = &proto_v6;
    }
    else
    {
        msg_log( L_ERR,
                 "%s: unknown peer family type\n",
                 __func__ );

        freeaddrinfo(res);
        quit( _EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    icmp_sockfd = socket( res->ai_family, SOCK_RAW, pr->icmp_proto );

    /*
     * make a RAW socket need permission,
     * it is usually use the 's' set-user-id by ping, man etc.
     * but we should give it up as soon as socket call finished
     */
    setuid( uid );

    if( icmp_sockfd < 0 )
    {
        msg_log( L_ERR,
                 "%s: socket fail, %s\n",
                 __func__,
                 strerror(errno));

        freeaddrinfo(res);
        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    /* since we get detail addr type, alloc memory below */
    pr->sa_peer = (struct sockaddr *) calloc( 1, res->ai_addrlen );
    pr->sa_from = (struct sockaddr *) calloc( 1, res->ai_addrlen );
    pr->sa_local = (struct sockaddr *) calloc( 1, res->ai_addrlen );
    pr->sa_len = res->ai_addrlen;
    bcopy( res->ai_addr, pr->sa_peer, res->ai_addrlen );

    if( res->ai_canonname != NULL )
    {
        /* fetch canonname */
        canonname = strdup( res->ai_canonname );
    }

    /* remember to free sockaddrinfo memory */
    freeaddrinfo(res);

    /*
     * if user special a data size that could hold a time structure,
     * then, do not add time info to packet when build packet later
     */
    if( datalen >= (int)sizeof( struct timeval ) )
    {
        contain_time = 1;
    }
    else
    {
        contain_time = 0;
    }

    /* call the detail-specialled type's initial function */
    pr->init( argc, argv );

    /* common init */
    init_common();

    /* initial signal handler */
    init_signal();
}



/* icmp4 initial func */
void    init_v4( int argc, char *argv[] )
{
    ((struct sockaddr_in *) pr->sa_local)->sin_family = AF_INET;
    ((struct sockaddr_in *) pr->sa_peer)->sin_family = AF_INET;

    /* specialled outgoing interface or address */
    if( globle_flags & F_IF_ADDR )
    {
        if( inet_pton( AF_INET,
                       interface, 
                       &((struct sockaddr_in *)pr->sa_local)->sin_addr ) != 1 )
        {
            /* interface is a device name */
            struct ifreq ifr;

            bzero( &ifr, sizeof(ifr) );

            strncpy( ifr.ifr_name, interface, IFNAMSIZ );

            /* fetch the interface info, no this interface if faild */
            if( ioctl( icmp_sockfd, SIOCGIFADDR, &ifr ) == -1 )
            {
                msg_log( L_ERR,
                         "%s (%s): ioctl fail, %s\n",
                         __func__,
                         interface,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            /* set outgoing interface */
            if( setsockopt( icmp_sockfd,
                            SOL_SOCKET,
                            SO_BINDTODEVICE,
                            ifr.ifr_name,
                            strlen(ifr.ifr_name) + 1 ) == -1 )
            {
                msg_log( L_ERR,
                         "%s: setsockopt(SO_BINDTODEVICE) fail, %s\n",
                         __func__,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            bcopy( &ifr.ifr_addr, pr->sa_local, pr->sa_len );
        }
        else
        {
            /* maybe I should fetch the interface name other than bind here */
            /*
            if( bind( icmp_sockfd, pr->sa_local, pr->sa_len ) != 0 )
            {
                msg_log( L_ERR,
                         "%s: bind error, %s\n",
                         __func__,
                         strerror(errno));

                quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
            }

            interface = NULL;
            */

            /* user special a outgoing address, now fetch the interface info */
            int i;
            char *buf;
            int size;
            int count = 10;
            struct ifconf ifc;
            struct ifreq *ifr;
            struct sockaddr_in *sin;

            for(;;)
            {
                buf = (char *)calloc( count, sizeof( struct ifreq ) );
                
                if( buf == NULL )
                {
                    msg_log( L_ERR,
                             "%s: out of memory\n",
                             __func__ );

                    quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
                }

                size = count * sizeof( struct ifreq );
                ifc.ifc_len = size;
                ifc.ifc_buf = buf;

                /* get interface list */
                if( ioctl( icmp_sockfd, SIOCGIFCONF, &ifc ) != 0 )
                {
                    if( errno != EINVAL )
                    {
                        msg_log( L_ERR,
                                 "%s (%s): ioctl fail, %s\n",
                                 __func__,
                                 interface,
                                 strerror(errno) );

                        free(buf);
                        buf = NULL;

                        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                    }
                    else
                    {
                        free(buf);
                        buf = NULL;
                        count += 10;
                        continue;
                    }
                }

                /*
                 * if giving memory is enough,
                 * then ifc.ifc_len should <= giving size.
                 * but in order to ensure all interfaces fetched,
                 * if ifc.ifc_len should == giving size,
                 * try again with a larger memory
                 */
                if( ifc.ifc_len < size )
                {
                    break;
                }

                free(buf);
                buf = NULL;
                count += 10;
            }

            for( i = 0, ifr = ifc.ifc_req;
                 i < ifc.ifc_len;
                 i += sizeof( struct ifreq ), ifr++ )
            {
                sin = (struct sockaddr_in *) &ifr->ifr_addr;

                if( sin->sin_family == AF_INET )
                {
//                    msg_log( L_ERR,
//                             "%s: %s\n",
//                             ifr->ifr_name,
//                             inet_ntoa( sin->sin_addr ));

                    /* compare the interface's addr to user specialled addr */
                    if( bcmp( &sin->sin_addr,
                              &((struct sockaddr_in *)pr->sa_local)->sin_addr,
                              sizeof( struct in_addr ) ) == 0 )
                    {
                        break;
                    }
                }
            }

            /* no interface whose address is user specialled addr  */
            if( i >= ifc.ifc_len )
            {
                msg_log( L_ERR,
                         "%s: no interface whose address is %s\n",
                         __func__,
                         interface );

                free(buf);
                buf = NULL;
                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            interface = strdup( ifr->ifr_name );
            free(buf);
            buf = NULL;

            /* set outgoing interface */
            if( setsockopt( icmp_sockfd,
                            SOL_SOCKET,
                            SO_BINDTODEVICE,
                            interface,
                            strlen(interface) + 1 ) == -1 )
            {
                msg_log( L_ERR,
                         "%s: setsockopt(SO_BINDTODEVICE) fail, %s\n",
                         __func__,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }
        }
    }

    /* set source route */
    if( globle_flags & F_SOURCERT )
    {
        __u8 *ptr, *bak;
        struct addrinfo *res;
        struct sockaddr_in *sin;

        if( argc - optind > 10 )
        {
            msg_log( L_ERR,
                     "%s: source route of IPv4 could not be more than 9\n",
                     __func__ );

            quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }

        if( (ptr  = (__u8 *)calloc( 1, 40 )) == NULL )
        {
            msg_log( L_ERR,
                     "%s: calloc fail\n",
                     __func__ );

            quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
        }

        bak = ptr;

        *ptr++ = IPOPT_NOP;
        
        /*
         * if specialled F_BYPASSRT flags,
         * use IPOPT_SSRR, otherwise IPOPT_LSRR
         */
        *ptr++ = (globle_flags & F_BYPASSRT) ? IPOPT_SSRR : IPOPT_LSRR;

        /*
         * should contain the destination address at the end ??
         * as unp says, it should,
         * but if see the packet dump,
         * there will be two same destination address at the end.
         * and the release version ping of ubuntu 
         * does not contain the destination address at the end.
         */
        /* here not contain the destination address at the end */
        *ptr++ = 3 + (argc - optind - 1) * 4;   /* not include the NOP */
        *ptr++ = 4;

        /*  */
        for( ; optind < argc - 1; optind++ )
        {
            res = host_addr( argv[optind], AF_INET, SOCK_DGRAM, 0 );

            if( res == NULL )
            {
                free(bak);
                bak = NULL;

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }
            else
            {
                sin = (struct sockaddr_in *) res->ai_addr;
                bcopy( &sin->sin_addr, ptr, sizeof(struct in_addr) );
                ptr += 4;
                freeaddrinfo(res);
            }
        }

        if( setsockopt( icmp_sockfd, 
                        IPPROTO_IP, 
                        IP_OPTIONS, 
                        bak, 
                        ptr - bak ) != 0 )
        {
            msg_log( L_ERR,
                     "%s: setsockopt(IP_OPTIONS) fail, %s\n",
                     __func__,
                     strerror(errno));
            free(bak);
            bak = NULL;
            quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
        }

        free(bak);
        bak = NULL;
        ip_optlen += 40;
    }

    /* set the broadcast option to the socket */
    if( globle_flags & F_BROADCAST )
    {
        int on = 1;

        /*  */
        if( setsockopt( icmp_sockfd, 
                        SOL_SOCKET, 
                        SO_BROADCAST, 
                        &on, 
                        sizeof(int) ) == -1 )
        {
            msg_log( L_ERR,
                     "%s: setsockopt(SO_BROADCAST) fail, %s\n",
                     __func__,
                     strerror(errno) );

            quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }
    }

    /* record route */
    if( globle_flags & F_RECORDRT )
    {
        /* if set F_SOURCERT already, then skip this step */
        if( ~globle_flags & F_SOURCERT )
        {
            __u8 *ptr, *bak;

            ptr  = (__u8 *)calloc( 1, 40 );

            bak = ptr;

            *ptr++ = IPOPT_NOP;
            *ptr++ = IPOPT_RR;
            *ptr++ = 39;
            *ptr++ = 4;

            if( setsockopt(icmp_sockfd, IPPROTO_IP, IP_OPTIONS, bak, 40) == -1 )
            {
                msg_log( L_ERR,
                         "%s: setsockopt(IP_OPTIONS) fail, %s\n",
                         __func__,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            ip_optlen += 40;
        }
    }

    /* deal with tll */
    /* IP_TTL */
    if( setsockopt( icmp_sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl) ) == -1 )
    {
        msg_log( L_ERR,
                 "%s: setsockopt(IP_TTL) fail, %s\n",
                 __func__,
                 strerror(errno) );

        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    /* IP_MULTICAST_TTL */
    if( setsockopt( icmp_sockfd, 
                    IPPROTO_IP, 
                    IP_MULTICAST_TTL, 
                    &ttl, 
                    sizeof(ttl) ) == -1 )
    {
        msg_log( L_ERR,
                 "%s: setsockopt(IP_MULTICAST_TTL) fail, %s\n",
                 __func__,
                 strerror(errno) );

        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }
}



/* icmp6 initial func */
void    init_v6( int argc, char *argv[] )
{
    /* IPv6 not support broadcast */
    if( globle_flags & F_BROADCAST )
    {
        msg_log( L_ERR,
                 "%s: IPv6 not support broadcast\n",
                 __func__ );

        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    ((struct sockaddr_in6 *) pr->sa_local)->sin6_family = AF_INET6;
    ((struct sockaddr_in6 *) pr->sa_peer)->sin6_family = AF_INET6;

    /* specialled outgoing interface or address */
    if( globle_flags & F_IF_ADDR )
    {
        if( inet_pton( AF_INET6, 
                interface, 
                &((struct sockaddr_in6 *)pr->sa_local)->sin6_addr ) != 1 )
        {
            /* interface is a device name */
            struct ifreq ifr;

            bzero( &ifr, sizeof(ifr) );

            strncpy( ifr.ifr_name, interface, IFNAMSIZ );

            /* fetch the interface info, no this interface if faild */
            if( ioctl( icmp_sockfd, SIOCGIFADDR, &ifr ) == -1 )
            {
                msg_log( L_ERR,
                         "%s (%s): ioctl fail, %s\n",
                         __func__,
                         interface,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            /* set outgoing interface */
            if( setsockopt( icmp_sockfd,
                            SOL_SOCKET,
                            SO_BINDTODEVICE,
                            ifr.ifr_name,
                            strlen(ifr.ifr_name) + 1 ) == -1 )
            {
                msg_log( L_ERR,
                         "%s: setsockopt(SO_BINDTODEVICE) fail, %s\n",
                         __func__,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            bcopy( &ifr.ifr_addr, pr->sa_local, pr->sa_len );
        }
        else
        {
            /* maybe I should fetch the interface name other than bind here */
            /*
            if( bind( icmp_sockfd, pr->sa_local, pr->sa_len ) != 0 )
            {
                msg_log( L_ERR,
                         "%s: bind error, %s\n",
                         __func__,
                         strerror(errno));

                quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
            }

            interface = NULL;
            */

            /* user special a outgoing address, now fetch the interface info */
            int i;
            char *buf;
            int size;
            int count = 10;
            struct ifconf ifc;
            struct ifreq *ifr;
            struct sockaddr_in6 *sin;

            for(;;)
            {
                buf = (char *)calloc( count, sizeof( struct ifreq ) );
                
                if( buf == NULL )
                {
                    msg_log( L_ERR,
                             "%s: out of memory\n",
                             __func__ );

                    quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
                }

                size = count * sizeof( struct ifreq );
                ifc.ifc_len = size;
                ifc.ifc_buf = buf;

                /* get interface list */
                if( ioctl( icmp_sockfd, SIOCGIFCONF, &ifc ) != 0 )
                {
                    if( errno != EINVAL )
                    {
                        msg_log( L_ERR,
                                 "%s (%s): ioctl fail, %s\n",
                                 __func__,
                                 interface,
                                 strerror(errno) );

                        free(buf);
                        buf = NULL;

                        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                    }
                    else
                    {
                        free(buf);
                        buf = NULL;
                        count += 10;
                        continue;
                    }
                }

                /*
                 * if giving memory is enough,
                 * then ifc.ifc_len should <= giving size.
                 * but in order to ensure all interfaces fetched,
                 * if ifc.ifc_len should == giving size,
                 * try again with a larger memory
                 */
                if( ifc.ifc_len < size )
                {
                    break;
                }

                free(buf);
                buf = NULL;
                count += 10;
            }

            for( i = 0, ifr = ifc.ifc_req;
                 i < ifc.ifc_len; 
                 i += sizeof( struct ifreq ), ifr++ )
            {
                sin = (struct sockaddr_in6 *) &ifr->ifr_addr;

                if( sin->sin6_family == AF_INET6 )
                {
//                    msg_log( L_ERR,
//                             "%s: %s\n",
//                             ifr->ifr_name,
//                             inet_ntoa( sin->sin_addr ));

                    /* compare the interface's addr to user specialled addr */
                    if( bcmp( &sin->sin6_addr,
                              &((struct sockaddr_in6 *)pr->sa_local)->sin6_addr,
                              sizeof( struct in6_addr ) ) == 0 )
                    {
                        break;
                    }
                }
            }

            /* no interface whose address is user specialled addr  */
            if( i >= ifc.ifc_len )
            {
                msg_log( L_ERR,
                         "%s: no interface whose address is %s\n",
                         __func__,
                         interface );

                free(buf);
                buf = NULL;
                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            interface = strdup( ifr->ifr_name );
            free(buf);
            buf = NULL;

            /* set outgoing interface */
            if( setsockopt( icmp_sockfd,
                            SOL_SOCKET,
                            SO_BINDTODEVICE,
                            interface,
                            strlen(interface) + 1 ) == -1 )
            {
                msg_log( L_ERR,
                         "%s: setsockopt(SO_BINDTODEVICE) fail, %s\n",
                         __func__,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }
        }
    }

    /* if special source route, build here, but send in send_v6 */
    if( globle_flags & F_SOURCERT )
    {
        struct addrinfo *res;

#if IPV6_STICKY
        void *v6_source_rt;
        socklen_t v6_source_rt_len;
#endif  /* IPV6_STICKY */

        /* IPv6 source route do not contain destination addr */
        v6_source_rt_len = inet6_rth_space( IPV6_RTHDR_TYPE_0, 
                                            argc - optind - 1 );
        if( v6_source_rt_len <= 0 )
        {
            msg_log( L_ERR,
                     "%s: wrong v6_source_rt_len \n",
                     __func__ );

            quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
        }

        v6_source_rt = calloc( 1, v6_source_rt_len );
        if( v6_source_rt == NULL )
        {
            msg_log( L_ERR,
                     "%s: out of memory!\n",
                     __func__ );

            quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
        }
        else
        {
            msg_log( L_ERR,
                     "%s: %d -- alloc %d\n",
                     __func__,
                     argc - optind - 1,
                     v6_source_rt_len);
        }

        if( inet6_rth_init( v6_source_rt, 
                            v6_source_rt_len, 
                            IPV6_RTHDR_TYPE_0, 
                            argc - optind - 1 ) == NULL )
        {
            msg_log( L_ERR,
                     "%s: inet6_rth_init error!\n",
                     __func__ );

            quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
        }

        for( ; optind < argc - 1; optind++ )
        {
            res = host_addr( argv[optind], AF_INET6, SOCK_DGRAM, 0 );

            if( res == NULL )
            {
                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }
            else
            {
                if( inet6_rth_add( v6_source_rt, 
                    &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr ) == -1 )
                {
                    msg_log( L_ERR,
                             "%s: inet6_rth_add error!\n",
                             __func__ );

                    freeaddrinfo(res);
                    quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
                }

                freeaddrinfo(res);
            }
        }

#if IPV6_STICKY

        /* try to use IPv6 sticky option */
        if( setsockopt( icmp_sockfd, 
                        IPPROTO_IPV6, 
                        IPV6_RTHDR, 
                        v6_source_rt, 
                        v6_source_rt_len ) == -1 )
        {
            msg_log( L_ERR,
                     "%s: setsockopt(IPV6_RTHDR) fail, %s\n",
                     __func__,
                     strerror(errno) );

            free(v6_source_rt);
            quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }

        free(v6_source_rt);
        v6_source_rt = NULL;

#endif /* IPV6_STICKY */

        ip_optlen += v6_source_rt_len;
    }

    /* special record route flag, set it to socket option */
    if( globle_flags & F_RECORDRT )
    {
        int on = 1;

        if( setsockopt( icmp_sockfd, 
                        IPPROTO_IPV6, 
                        IPV6_RECVRTHDR, 
                        &on, 
                        sizeof(on) ) == -1 )
        {
            msg_log( L_ERR,
                     "%s: setsockopt(IPV6_RECVRTHDR) fail, %s\n",
                     __func__,
                     strerror(errno) );

            quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }
    }

    /* deal with tll */
    /* IP_TTL */
    if( setsockopt( icmp_sockfd, 
                    IPPROTO_IPV6, 
                    IPV6_UNICAST_HOPS, 
                    &ttl, 
                    sizeof(ttl) ) == -1 )
    {
        msg_log( L_ERR,
                 "%s: setsockopt(IPV6_UNICAST_HOPS) fail, %s\n",
                 __func__,
                 strerror(errno) );

        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    /* IP_MULTICAST_TTL */
    if( setsockopt( icmp_sockfd, 
                    IPPROTO_IPV6, 
                    IPV6_MULTICAST_HOPS, 
                    &ttl, 
                    sizeof(ttl) ) == -1 )
    {
        msg_log( L_ERR,
                 "%s: setsockopt(IPV6_MULTICAST_HOPS) fail, %s\n",
                 __func__,
                 strerror(errno) );

        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }

    /* icmp6 filter */
    {
        int on = 1;
        struct icmp6_filter filter;

        ICMP6_FILTER_SETBLOCKALL( &filter );

        /*
         * will only receive ICMP6_ECHO_REPLY, 
         * so proc_err_v6(...) may be never called
         */
        ICMP6_FILTER_SETPASS( ICMP6_ECHO_REPLY, &filter );

        setsockopt( icmp_sockfd, 
                    IPPROTO_IPV6, 
                    ICMP6_FILTER, 
                    &filter, 
                    sizeof(filter) );// == -1 )
//        {
//            msg_log( L_ERR,
//                     "%s: setsockopt(ICMP6_FILTER) fail, %s\n",
//                     __func__,
//                     strerror(errno) );
//        }

        setsockopt( icmp_sockfd, 
                    IPPROTO_IPV6, 
                    IPV6_RECVHOPLIMIT, 
                    &on, 
                    sizeof(on) );// == -1 )
//        {
//            msg_log( L_ERR,
//                     "%s: setsockopt(IPV6_RECVHOPLIMIT) fail, %s\n",
//                     __func__,
//                     strerror(errno) );
//        }
    }
}



/* icmp common initial func */
void    init_common()
{
    /* set recv socket buffer size */
    if( setsockopt( icmp_sockfd,
                    SOL_SOCKET,
                    SO_RCVBUF,
                    &s_recvbuf,
                    sizeof(s_recvbuf) ) == -1 )
    {
        /*
         * default set it to 10*1024,
         * if fail, kernal will set it to a proper one
         */
    }

    /* set send socket buffer size */
    /* if user special a socket send buffer size, then set it */
    if( s_sendbuf > 0 )
    {
        if( setsockopt( icmp_sockfd,
                        SOL_SOCKET,
                        SO_SNDBUF,
                        &s_sendbuf,
                        sizeof(s_sendbuf) ) == -1 )
        {
            /* should exit if fail, or use the prev-system-default */
            msg_log( L_ERR,
                     "%s(SO_SNDBUF): setsockopt error, %s\n",
                     __func__,
                     strerror(errno));
        }
    }

    /* bind to a special local address */
    if( globle_flags & F_BIND )
    {
        if( globle_flags & F_IF_ADDR )
        {
            /*
             * since F_IF_ADDR will get local addr, so just bind below
             * I don't know SO_BINDTODEVICE and bind address is equivslent
             */
            if( bind( icmp_sockfd, pr->sa_local, pr->sa_len ) != 0 )
            {
                msg_log( L_ERR,
                         "%s: bind error, %s\n",
                         __func__,
                         strerror(errno));

                quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
            }
        }
        else
        {
            /* local addr is unknown till now, get one by use connect */
            if( connect( icmp_sockfd, pr->sa_peer, pr->sa_len ) != 0 )
            {
                if( errno == EACCES || errno == EPERM )
                {
                    if( ~globle_flags & F_BROADCAST )
                    {
                        msg_log( L_ERR,
                                 "%s: you may ping a broadcast address \
                                 without -b option\n",
                                 __func__);
                    }
                }

                msg_log( L_ERR,
                         "%s: could not connect to peer, %s\n",
                         __func__,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
            }

            /* get bound addr */
            if( getsockname( icmp_sockfd, pr->sa_local, &pr->sa_len ) == -1 )
            {
                msg_log( L_ERR,
                         "%s: getsockname fail, %s\n",
                         __func__,
                         strerror(errno) );

                quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
            }
//
//            msg_log( L_ERR,
//                   "ip:%s\tport:%d\n",
//                   inet_ntoa(((struct sockaddr_in *) pr->sa_local)->sin_addr),
//                   ntohs(((struct sockaddr_in *) pr->sa_local)->sin_port));
        }
    }

    /* special to bypass the route, set it to socket option */
    if( globle_flags & F_BYPASSRT )
    {
        int on = 1;

        if( setsockopt( icmp_sockfd, 
                        SOL_SOCKET, 
                        SO_DONTROUTE, 
                        &on, 
                        sizeof(on)) == -1 )
        {
            msg_log( L_ERR,
                     "%s: setsockopt(SO_DONTROUTE) fail, %s\n",
                     __func__,
                     strerror(errno) );

            quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }
    }

    /* special timeout option, set receive timeout */
    if( globle_flags & F_TIMEOUT )
    {
        struct timeval tv;

        double2tv ( &tv, timeout );

        if( setsockopt( icmp_sockfd, 
                        SOL_SOCKET, 
                        SO_RCVTIMEO, 
                        &tv, 
                        sizeof(tv) ) == -1 )
        {
            msg_log( L_ERR,
                     "%s: setsockopt(SO_RCVTIMEO) fail, %s\n",
                     __func__,
                     strerror(errno) );

            quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
        }
    }

    /* deal with the value of default interval */
    if( ~globle_flags & F_INTERVAL )
    {
        /*
         * if special adaptive ping, then set interval to MIN_USR_INTERVAL
         * it is mainly for normal user,
         * bcause root always send as soon as recv one
         */
        if( globle_flags & F_ADAPTIVE )
        {
            interval = (double)MIN_USR_INTERVAL / SEC2MSEC;
        }

        /* special flood ping */
        if( globle_flags & F_FLOOD )
        {
            //interval = (double)DFL_FLOOD_INTERVAL / SEC2MSEC;
            if( uid != 0 )
            {
                /*
                 * if normal user use a interval less than MIN_USR_INTERVAL, 
                 * return wrong 
                 */
                if( DFL_FLOOD_INTERVAL < MIN_USR_INTERVAL )
                {
                    msg_log( L_ERR,
                             "%s: cannot flood, \
                             minimal interval allowed for user is %dms\n",
                             __func__,
                             MIN_USR_INTERVAL );

                    quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
                }
            }
        }
    }
    else
    {
        /*
         * if interval is equal to zero, it is means flood ping
         * only root can run here
         */
        if( interval <= EPSINON )
        {
            globle_flags |= F_FLOOD;
            interval = (double)DFL_FLOOD_INTERVAL / SEC2MSEC;
        }
    }

    /* if special flood ping, set the stdout, stderr nonbuffer */
    if( globle_flags & F_FLOOD )
    {
        /* flood print only '.', here change buffer mode to nonbuffered */
        setvbuf( stdout, NULL, _IONBF, 0 );

        /*
         * in fact, 
         * stderr refer to a terminal is normally nonbuffered,
         * just in case 
         */
        setvbuf( stderr, NULL, _IONBF, 0 );
    }
}



/* initial signal handler */
void    init_signal()
{
    struct sigaction sig_alrm, sig_int;

    /* timer signal */
    sig_alrm.sa_handler = sig_handler;
    sig_alrm.sa_flags = SA_RESTART;

    /* Ctrl + C signal */
    sig_int.sa_handler = sig_handler;
    sig_int.sa_flags = 0;

    if( sigaction( SIGALRM, &sig_alrm, NULL ) == -1
        || sigaction( SIGINT, &sig_int, NULL ) == -1
        || sigaction( SIGQUIT, &sig_int, NULL ) == -1)
    {
        msg_log( L_ERR,
                 "%s: set signal handler fail, %s\n",
                 __func__,
                 strerror(errno));

        quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
    }
}



/* icmp4 packet parser */
int proc_v4( char *buf, 
             ssize_t len,
             struct msghdr *msg, 
             struct timeval *tv_recv )
{
    int ip_hdrlen;
    int icmp_len;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tv_send = NULL;

    ip = (struct ip *) buf;

    if( ip->ip_p != IPPROTO_ICMP )
    {
        return -1;
    }

    /*
     * since the 4 bit ip 'header length' giving the ip header length 
     * in 32-bit words,
     * so it stands for the 4 times byte than its value
     */
    //ip->ip_hl = ip->ip_hl << 2;
    ip_hdrlen = ip->ip_hl << 2;

    if( (icmp_len = len - ip_hdrlen) < ICMPHDR_LEN )
    {
        return -1;
    }

    icmp = (struct icmp *) (buf + ip_hdrlen);

    /* icmp echo reply */
    if( icmp->icmp_type == ICMP_ECHOREPLY )
    {
        /* not belong to us */
        if( icmp->icmp_id != pid )
        {
            return -1;
        }

//        if( icmp->icmp_seq < recvnum )
//        {
//            return;
//        }

//        if( icmp->icmp_seq == recvnum )
//        {
//            /* dup */
//            /* should I do something ? */
//            return;
//        }

        recvnum++;

        /* print as the way in flood ping */
        if( globle_flags & F_FLOOD )
        {
            msg_log( L_RESULT, "\b \b" );
            lr = icmp->icmp_seq;

            if( contain_time == 1 )
            {
                if( icmp_len < (int)sizeof( struct timeval ) + ICMPHDR_LEN )
                {
                    /* require time, but it does not contain */
                    return -1;
                }

                tv_send = (struct timeval *) icmp->icmp_data;
                tv_sub( tv_recv, tv_send );

                /* update min, max, total time value */
                update_tv_data(tv_recv);
            }

            return 0;
        }

        if( contain_time == 1 )
        {
            if( icmp_len < (int)sizeof( struct timeval ) + ICMPHDR_LEN )
            {
                /* require time, but it does not contain */
                //return;
            }
            else
            {
                tv_send = (struct timeval *) icmp->icmp_data;
                tv_sub( tv_recv, tv_send );

                update_tv_data(tv_recv);
            }
        }

        if( tv_send != NULL )
        {
            show_reply( icmp->icmp_type, 
                        icmp->icmp_code, 
                        msg, 
                        icmp_len, 
                        icmp->icmp_seq, 
                        ip->ip_ttl, 
                        tv_recv );
        }
        else
        {
            show_reply( icmp->icmp_type, 
                        icmp->icmp_code, 
                        msg, 
                        icmp_len, 
                        icmp->icmp_seq, 
                        ip->ip_ttl, 
                        NULL );
        }

        /* print source route if needed */
        if( globle_flags & F_RECORDRT )
        {
            if( ip_hdrlen - sizeof( struct ip ) <= 0 )
            {
                msg_log( L_ERR,
                         "%s: request source route, but there's no data!\n",
                         __func__);
            }
            else
            {
                pr_source_rt_v4( (__u8 *)buf + sizeof( struct ip ), 
                                 ip_hdrlen - sizeof( struct ip ) );
            }
        }

        lr = icmp->icmp_seq;

        return 0;
    }
    else
    {
        /* deal other type icmp packet */
        return proc_err_v4( msg, len, icmp, icmp_len );
    }
}


/*
 * parse other icmp4 type msg
 * *only update lr
 */
int proc_err_v4( const struct msghdr *msg, 
                 int len, 
                 struct icmp *icmp, 
                 int icmp_len )
{
    struct ip *ip;
    __u8 err_code;
    __u8 icmp_type;
    __u8 ip_hdrlen;

    /*
     * IPv4 -- destination unreachable, Time Exceeded, Source Quench
     *   0                   1                   2                   3
     *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |     Type      |     Code      |          Checksum             |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |                             unused                            |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |      Internet Header + 64 bits of Original Data Datagram      |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /* minium len: icmp hdr + ip hdr + icmp hdr = 8 + 20 + 8 = 36 */
    if( len < ICMPHDR_LEN + \
              (int)sizeof(struct ip) + \
              ICMPHDR_LEN )
    {
        return -1;
    }

    err_code = icmp->icmp_code;
    icmp_type = icmp->icmp_type;

    /* icmp type that not interest */
    if( icmp_type != ICMP_DEST_UNREACH
        && icmp_type != ICMP_TIME_EXCEEDED
        && icmp_type != ICMP_SOURCE_QUENCH )
    {
        return -1;
    }

    ip = (struct ip *) ((__u8 *)icmp + ICMPHDR_LEN);

    ip_hdrlen = ip->ip_hl << 2;

    /* there is no enough size to contain a icmp packet */
    if( icmp_len - ICMPHDR_LEN - ip_hdrlen < ICMPHDR_LEN )
    {
        return -1;
    }

    icmp = (struct icmp *) ((__u8 *) ip + ip_hdrlen);

    if( icmp->icmp_id != pid )
    {
        return -1;
    }

    /* here is the returned icmp packet */
    show_reply( icmp_type, 
                err_code, 
                msg, 
                len, 
                icmp->icmp_seq, 
                ip->ip_ttl, 
                NULL );

    errnum++;
    lr = icmp->icmp_seq;

    return 0;
}



/* icmp6 packet parser */
int proc_v6( char *buf, 
             ssize_t len, 
             struct msghdr *msg, 
             struct timeval *tv_recv )
{
    struct icmp6_hdr *icmp6;
    struct timeval *tv_send = NULL;
    struct cmsghdr *cmsg, *rt_cmsg = NULL;
    int hop_limit = -1;

    if( len < ICMPHDR_LEN )
    {
        return -1;
    }

    icmp6 = ( struct icmp6_hdr * ) buf;

    /* icmp echo reply */
    if( icmp6->icmp6_type == ICMP6_ECHO_REPLY )
    {
        if( icmp6->icmp6_id != pid )
        {
            return -1;
        }

        recvnum++;

        /* print as the way in flood ping */
        if( globle_flags & F_FLOOD )
        {
            msg_log( L_RESULT, "\b \b" );
            lr = icmp6->icmp6_seq;

            if( contain_time == 1 )
            {
                if( len < (int)sizeof( struct timeval ) + ICMPHDR_LEN )
                {
                    /* require time, but it does not contain */
                    ;
                }
                else
                {
                    tv_send = (struct timeval *) (icmp6 + 1);
                    tv_sub( tv_recv, tv_send );

                    update_tv_data(tv_recv);
                }
            }

            return 0;
        }

        if( contain_time == 1 )
        {
            /* consider ancillary length ??? */
//            if( icmp_len < (int)sizeof( struct timeval ) + 8 )
//            {
//                /* require time, but it does not contain */
//                return;
//            }

            tv_send = (struct timeval *) (icmp6 + 1);
            tv_sub( tv_recv, tv_send );

            update_tv_data(tv_recv);
        }

        /* get time and source route if have */
        for( cmsg = CMSG_FIRSTHDR(msg);
             cmsg != NULL;
             cmsg = CMSG_NXTHDR(msg, cmsg) )
        {
            if( cmsg->cmsg_level == IPPROTO_IPV6 )
            {
                /* IPV6_HOPLIMIT */
                if( cmsg->cmsg_type == IPV6_HOPLIMIT )
                {
                    hop_limit = (int) (*( __u8 * ) CMSG_DATA(cmsg));

                    if( globle_flags & F_RECORDRT )
                    {
                        if( rt_cmsg != NULL  )
                        {
                            break;
                        }
                    }
                    else
                    {
                        break;
                    }
                }

                if( globle_flags & F_RECORDRT
                    && cmsg->cmsg_type == IPV6_RTHDR )
                {
                    rt_cmsg = cmsg;

                    if( hop_limit >= 0 )
                    {
                        break;
                    }
                }
            }
        }

        if( tv_send != NULL )
        {
            show_reply( icmp6->icmp6_type,
                        icmp6->icmp6_code, 
                        msg, 
                        len, 
                        icmp6->icmp6_seq, 
                        hop_limit, 
                        tv_recv );
        }
        else
        {
            show_reply( icmp6->icmp6_type, 
                        icmp6->icmp6_code, 
                        msg, 
                        len, 
                        icmp6->icmp6_seq, 
                        hop_limit, 
                        NULL );
        }

        if( globle_flags & F_RECORDRT )
        {
            if( rt_cmsg == NULL )
            {
                msg_log( L_ERR,
                         "%s: missing route record!\n",
                         __func__ );
            }
            else
            {
                pr_source_rt_v6( rt_cmsg );
            }
        }

        lr = icmp6->icmp6_seq;

        return 0;
    }
    else
    {
        /* deal other type icmp packet */
        /* not finish here because the don't know way to test icmp6 */
        return proc_err_v6( msg, len, icmp6, len - msg->msg_controllen );
    }
}



/*
 * parse other icmp4 type msg
 * ! only update lr
 */
int proc_err_v6( const struct msghdr *msg, 
                 int len, 
                 struct icmp6_hdr *icmp6, 
                 int icmp6_len )
{
    __u8 err_code;
    __u8 icmp6_type;

    /*
     * ICMPv6 -- Destination Unreachable,
     *
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |     Type      |     Code      |          Checksum             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                             Unused                            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                    As much of invoking packet                 |
     * +                as possible without the ICMPv6 packet          +
     * |                exceeding the minimum IPv6 MTU [IPv6]          |
     */

    /* minium len: icmp6 hdr + icmp hdr = 8 + 8 = 16 */
    if( icmp6_len < ICMPHDR_LEN + ICMPHDR_LEN )
    {
        return -1;
    }

    err_code = icmp6->icmp6_code;
    icmp6_type = icmp6->icmp6_type;

    /* icmp6 type that not interest */
    if( icmp6_type != ICMP6_DST_UNREACH
        && icmp6_type != ICMP6_PACKET_TOO_BIG
        && icmp6_type != ICMP6_TIME_EXCEEDED )
    {
        return -1;
    }

    icmp6++;

    if( icmp6->icmp6_id != pid )
    {
        return -1;
    }

    /* here is the returned icmp6 packet */
    show_reply( icmp6_type, err_code, msg, len, icmp6->icmp6_seq, -1, NULL );

    errnum++;
    lr = icmp6->icmp6_seq;

    return 0;
}



/* send packet, to control diff icmp types and preload */
void    send_icmp()
{
    pr->send();

    /* the loop may delay the recv time !!! to be fixed */
    while( seqnum <= lr + preload )
    {
        /* do something else if needed */

        /* !!! remember to check interval since last send for normal user */
        if( check_send_interval() == 0 )
        {
            pr->send();
        }
        else
        {
            return;
        }
    }
}



/* send icmp4 packet */
void    send_v4()
{
    int len = ICMPHDR_LEN + datalen;
    struct icmp *icmp;

    icmp = (struct icmp *) send_buf;

    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = pid;
    
    /*
     * maybe here should convert to network byte order,
     * but in fact it is OK if we can recogonize it self.
     * considering third-party, we shall use network byte order
     */
    icmp->icmp_seq = seqnum++;

    bzero( icmp->icmp_data, datalen );
    //memset( icmp->icmp_data, 0xa5, datalen );

    if( contain_time == 1 )
    {
        gettimeofday( (struct timeval *) icmp->icmp_data, NULL );
    }

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = in_cksum( (__u16 *) icmp, len );

    for(;;)
    {
        //print_packet( send_buf, len );
         int n = sendto( icmp_sockfd, 
                         send_buf, 
                         len, 
                         0, 
                         pr->sa_peer, 
                         pr->sa_len );

         if( n == -1 )
         {
             if( errno == EINTR )
             {
                 continue;
             }
             else
             {
                 msg_log( L_ERR,
                          "%s: send error, %s\n",
                          __func__,
                          strerror(errno));
                 /* should exit or return */
//                 exit(ERR_SYSTEM);
                 return;
             }
         }

         if( n != len )
         {
             /* ??? */
             continue;
         }

         break;
    }

    /* update last seng packet time */
    gettimeofday( &tv_lsend, NULL );

    /* print as the way in flood ping */
    if( globle_flags & F_FLOOD )
    {
        msg_log( L_RESULT, "." );
    }
}



/* send icmp6 packet */
void    send_v6()
{
    struct msghdr msg;
    struct iovec iov;
    int len = ICMPHDR_LEN + datalen;
    struct icmp6_hdr *icmp6;

    /* build icmp6 hdr */
    icmp6 = (struct icmp6_hdr *) send_buf;

    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id = pid;
    
    /*
     * maybe here should convert to network byte order,
     * but in fact it is OK if we can recogonize it self.
     * considering third-party, we shall use network byte order
     */
    icmp6->icmp6_seq = seqnum++;

    bzero( icmp6 + 1, datalen );
    //memset( icmp6 + 1, 0xa5, datalen );

    /* add time if needed */
    if( contain_time == 1 )
    {
        gettimeofday( (struct timeval *) (icmp6 + 1), NULL );
    }

    /* add source route as ancillary data if needed */
    if( globle_flags & F_SOURCERT )
    {
#if IPV6_STICKY
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
#else
        msg.msg_control = v6_source_rt;
        msg.msg_controllen = v6_source_rt_len;
#endif  /* IPV6_STICKY */
    }
    else
    {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    /* add peer addr if not bound or connected */
    if( ~globle_flags & F_BIND )
    {
        msg.msg_name = pr->sa_peer;
        msg.msg_namelen = pr->sa_len;
    }
    else
    {
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
    }

    iov.iov_base = send_buf;
    iov.iov_len = len;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_flags = 0;

    for(;;)
    {
        //print_packet( send_buf, len );
        int n = sendmsg( icmp_sockfd, &msg, 0 );

         if( n == -1 )
         {
             if( errno == EINTR )
             {
                 continue;
             }
             else
             {
                 msg_log( L_ERR,
                          "%s: send error, %s\n",
                          __func__,
                          strerror(errno));

                 quit( EXIT_CALL | PACKET_STATE | ERR_SYSTEM );
             }
         }

         /* to be test: if the return size contain ancillary */
//         if( n != len )
//         {
//             /* ??? */
//             continue;
//         }

         break;
    }

    gettimeofday( &tv_lsend, NULL );

    /* print as the way in flood ping */
    if( globle_flags & F_FLOOD )
    {
        msg_log( L_RESULT, "." );
    }
}



/*
 * autorun after exit(...) called
 * clean all alloc memory
 */
void    exit_handler()
{
    /*
     * while coding,
     * remember to add every clean process here if use a alloced globle var
     */

    if( pr != NULL )
    {
        if( pr->sa_from != NULL )
        {
            free(pr->sa_from);
            pr->sa_from = NULL;
        }

        if( pr->sa_peer != NULL )
        {
            free(pr->sa_peer);
            pr->sa_peer = NULL;
        }

        if( pr->sa_local != NULL )
        {
            free(pr->sa_local);
            pr->sa_local = NULL;
        }
    }

#if ! IPV6_STICKY
    if( v6_source_rt != NULL )
    {
        free(v6_source_rt);
        v6_source_rt = NULL;
    }
#endif  /* IPV6_STICKY */

    if( canonname != NULL )
    {
        free(canonname);
        canonname = NULL;
    }
}



/* main signal handler */
void    sig_handler( int signo )
{
    if( signo == SIGALRM )
    {
        /* if special endline, then update it */
        if( globle_flags & F_ENDLINE )
        {
            deadline -= interval;

            if( deadline <= EPSINON )
            {
                quit( EXIT_CALL | PACKET_STATE | ERR_NONE );
            }
        }

        /* reach user specialled packet count */
        if( mount > 0 && seqnum >= mount )
        {
            /*
             * if special count and a deadline,
             * then proc only quit when recv such count packets
             * or endline timer expired
             */
            if( globle_flags & F_ENDLINE )
            {
                return;
            }

            if( is_in_parse == 0 )
            {
                /* delay 2 interval waitting for last reply */

                struct timeval tv_last;
                struct timeval tv_2interval;

                gettimeofday ( &tv_last, NULL );
                tv_sub ( &tv_last, &tv_lsend );
                double2tv( &tv_2interval, 2*interval );

                if( tv_cmp( &tv_last, &tv_2interval ) < 0 )
                {
                    return;
                }

                /* should delay sometime here */
                quit( EXIT_CALL | PACKET_STATE | ERR_NONE );
            }
            else
            {
                return;
            }
        }

        /*
         * if user special recv time but not special interval,
         * then not send when timer expired
         */
//        if( globle_flags & F_TIMEOUT
//            && ~globle_flags & F_INTERVAL )
//        {
//            return;
//        }

        /* if is parsing packet, then pend */
        if( is_in_parse == 1 )
        {
            is_pending_send = 1;
        }
        else
        {
            send_icmp();
            is_pending_send = 0;
        }
    }
    else if( signo == SIGINT )
    {
        /* start a new line to skip "^C" */
        msg_log( L_ERR, "\n" );

        /* stop timer anyway */
        stop_timer();

        show_result();

        quit( EXIT_CALL | PACKET_STATE | ERR_NONE );
    }
    else if( signo == SIGQUIT )
    {
        /* start a new line to skip "^\" */
        msg_log( L_ERR, "\b\b  \b\b" );
        show_status();
    }
}



/* print the icmp4 source route */
void    pr_source_rt_v4( const __u8 *ptr, int len )
{
    int n;
    const __u8 *end = ptr + len;
    char addrstr[128];
    char hoststr[128];

    /* store the latest unchanged source_rt */
    static int srt_len = 0;
    static int srt[44];

    //print_packet( ptr, len );

//    if( len < (int)sizeof( struct in_addr ) + 4 )
//    {
//        msg_log( L_ERR, "wrong option length\n" );
//        return;
//    }

    //bcopy( ptr, &hop1, sizeof( struct in_addr ) );
    //ptr += sizeof( struct in_addr );

    for( ; ptr < end && *ptr == IPOPT_NOP; ptr++ )
    {
        ;
    }

    if( ptr >= end )
    {
        return;
    }

    if( *ptr == IPOPT_LSRR )
    {
        msg_log( L_RESULT, "LSRR:\n" );
    }
    else if( *ptr == IPOPT_SSRR )
    {
        msg_log( L_RESULT, "SSRR:\n" );
    }
    else if( *ptr == IPOPT_RR )
    {
        msg_log( L_RESULT, "RR:\n" );
    }
    else
    {
        msg_log( L_ERR, "Unknown ip option type\n" );
        return;
    }

    //addr_ntop( AF_INET, &hop1, ~globle_flags & F_NUMERIC, 1, addrstr, 128 );

//    msg_log( L_RESULT,
//             "%s\n",
//             addrstr );

    n = *++ptr - 3;

    if( n < 0 || n > len )
    {
        msg_log( L_ERR, "wrong option length\n" );
        return;
    }

    ptr += 2;
    end = ptr + n;

    if( srt_len != n )
    {
        bcopy( ptr, srt, n );
        srt_len = n;
    }
    else
    {
        if( bcmp( ptr, srt, n ) == 0 )
        {
            msg_log( L_RESULT, "\t(same route)\n" );
            return;
        }
        else
        {
            bcopy( ptr, srt, n );
        }
    }

    while( ptr < end )
    {
        addr_ntop( ptr,
                   addrstr, 128,
                   hoststr, globle_flags & F_NUMERIC ? 0 : 128,
                   1);
        msg_log( L_RESULT,
                 "\t%s (%s)\n",
                 globle_flags & F_NUMERIC ? addrstr : hoststr,
                 addrstr);
        ptr += sizeof( struct in_addr );
    }

    msg_log( L_RESULT, "\n" );
}



/* print the icmp6 source route */
void    pr_source_rt_v6( struct cmsghdr *cmsg )
{
    char addrstr[128];
    char hoststr[128];
    int i, segments;

    if( cmsg == NULL )
    {
        msg_log( L_ERR,
                 "%s: null cmsg pointor!\n",
                 __func__ );
        return;
    }

    if( inet6_rth_reverse( cmsg, cmsg ) == -1 )
    {
        msg_log( L_ERR,
                 "%s: inet6_rth_reverse fail!\n",
                 __func__ );
        return;
    }

    segments = inet6_rth_segments( cmsg );

    if( segments <= 0 )
    {
        msg_log( L_ERR,
                 "%s: wrong segments!\n",
                 __func__ );
        return;
    }

    msg_log( L_RESULT, "RR:\n" );

    for( i = 0; i < segments; i++ )
    {
        addr_ntop( (void *)inet6_rth_getaddr( cmsg, i ),
                   addrstr, 128,
                   hoststr, globle_flags & F_NUMERIC ? 0 : 128,
                   1);
        msg_log( L_RESULT,
                 "\t%s (%s)\n",
                 globle_flags & F_NUMERIC ? addrstr : hoststr,
                 addrstr);
    }
}



/* print the banner begin any ping action */
void    pr_banner()
{
    char addrstr[128];

    addr_ntop( pr->sa_peer->sa_family == AF_INET ? \
               (void *) &((struct sockaddr_in *)pr->sa_peer)->sin_addr : \
               (void *) &((struct sockaddr_in6 *)pr->sa_peer)->sin6_addr,
               addrstr, 128,
               NULL, 0,
               1);

    if( canonname == NULL )
    {
        msg_log( L_RESULT,
                 "PING %s",
                 addrstr
                 );
    }
    else
    {
        msg_log( L_RESULT,
                 "PING %s (%s)",
                 canonname,
                 addrstr
                 );
    }

    if( globle_flags & F_IF_ADDR )
    {
        msg_log( L_RESULT,
                 " from %s %s",
                 addrstr,
                 interface != NULL ? interface : "\b" );
    }

    /* should IPv6 ancillary consider in ? */
    msg_log( L_RESULT,
             ": init ttl=%d, %d(%d) byte of data.\n",
             ttl,
             datalen,
             ip_optlen + datalen + ICMPHDR_LEN + IPHDR_LEN ); /* need fix, OK */
}



/* show the ping status current */
void    show_status()
{
    double avg_time, min_time, max_time;

    if( seqnum <= 0 )
    {
        msg_log( L_RESULT,
                 "no packet transmitted.\n" );
        return;
    }


    if( recvnum > 0 )
    {
        avg_time = tv2double ( &tv_total ) / recvnum;
        min_time = tv2double ( &tv_min );
        max_time = tv2double ( &tv_max );
    }
    else
    {
        avg_time = 0;
        min_time = 0;
        max_time = 0;
    }


    msg_log( L_RESULT,
             "%d/%d packets, %.2f%% received, \
             min/avg/max = %.2f/%.2f/%.2f ms\n",
             recvnum,
             seqnum,
             100 * (double)recvnum / (double)seqnum,
             min_time,
             avg_time,
             max_time );
}



/* show the ping result */
void    show_result()
{
    double run_time, avg_time, min_time, max_time;
    struct timeval tv_now;
    char addrstr[128];

    if( seqnum <= 0 )
    {
        msg_log( L_RESULT,
                 "no packet transmitted.\n" );
        return;
    }

    gettimeofday(&tv_now, NULL);
    tv_sub( &tv_now, &tv_begin );

    run_time = tv2double ( &tv_now );

    if( canonname == NULL )
    {
        addr_ntop( pr->sa_peer->sa_family == AF_INET ? \
                   (void *) &((struct sockaddr_in *)pr->sa_peer)->sin_addr : \
                   (void *) &((struct sockaddr_in6 *)pr->sa_peer)->sin6_addr,
                   addrstr, 128,
                   NULL, 0,
                   1);
    }

    msg_log( L_RESULT,
             "--- %s ping statistics ---\n",
             canonname == NULL ? addrstr : canonname );

    msg_log( L_RESULT,
             "total run time %.3f ms\n",
             run_time );

    msg_log( L_RESULT,
             "%d transmitted, %d(%.2f%%) received, \
             %d(%.2f%%) error, %d(%.2f%%) lost.\n",
             seqnum,
             recvnum,
             100.0 * (double)recvnum / (double)seqnum,
             errnum,
             100.0 * (double)errnum / (double)seqnum,
             seqnum - recvnum - errnum,
             ( 1.0 - (double)(recvnum + errnum) / (double)(seqnum) ) * 100 );

    if( recvnum > 0 )
    {
        avg_time = tv2double ( &tv_total ) / recvnum;
        min_time = tv2double ( &tv_min );
        max_time = tv2double ( &tv_max );

        msg_log( L_RESULT,
                 "rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
                 min_time,
                 avg_time,
                 max_time);
    }
}



/* print reply info after parse a icmp reply packet */
inline void    show_reply( int type, int code,
                           const struct msghdr *msg, int len,
                           __u16 rnr, int rttl,
                           const struct timeval *tv_cost )
{
    double rtv;
    char addrstr[128];

    /* quiet mode */
    if( globle_flags & F_QUITE )
    {
        return;
    }

    if( pr->sa_peer->sa_family == AF_INET )
    {
        /* only icmp type that we interest */
        if( type != ICMP_ECHOREPLY
            && type != ICMP_DEST_UNREACH
            && type != ICMP_TIME_EXCEEDED
            && type != ICMP_SOURCE_QUENCH )
            /* (type < 0 || type > MAX_ERR_TYPE) */
        {
            return;
        }

        /* unsupported code */
        if( code < 0 || code > MAX_ICMP4_ERR_CODE )
        {
            return;
        }
    }
    else
    {
        /* icmp6 type that not interest */
        if( type != ICMP6_ECHO_REPLY
            && type != ICMP6_DST_UNREACH
            && type != ICMP6_PACKET_TOO_BIG
            && type != ICMP6_TIME_EXCEEDED )
        {
            return;
        }

        if( code < 0 || code > MAX_ICMP6_ERR_CODE )
        {
            return;
        }
    }

    if( globle_flags & F_NUMERIC )
    {
        addr_ntop( pr->sa_peer->sa_family == AF_INET ? \
                   (void *) &((struct sockaddr_in *)msg->msg_name)->sin_addr : \
                   (void *) &((struct sockaddr_in6 *)msg->msg_name)->sin6_addr,
                   addrstr, 128,
                   NULL, 0,
                   1);
    }
    else
    {
        addr_ntop( pr->sa_peer->sa_family == AF_INET ? \
                   (void *) &((struct sockaddr_in *)msg->msg_name)->sin_addr : \
                   (void *) &((struct sockaddr_in6 *)msg->msg_name)->sin6_addr,
                   NULL, 0,
                   addrstr, 128,
                   1);
    }

    if( tv_cost != NULL )
    {
        rtv = tv2double ( tv_cost );

        msg_log( L_RESULT,
                 "%d bytes from %s: icmp_seq=%-3d ttl=%-2d time=%-5.2f ms %s\n",
                 len,
                 addrstr,
                 rnr + 1,
                 rttl,
                 rtv,
                 rnr == lr ? "(dup)" : "");
    }
    else
    {
        /* error type icmp or null time packet should run here */

        msg_log( L_RESULT,
                 "%d bytes from %s: icmp_seq=%-3d ttl=%-2d %s %s\n",
                 len,
                 addrstr,
                 rnr + 1,
                 rttl,
                 pr->sa_peer->sa_family == AF_INET ? \
                 icmp4_err[type][code] == NULL ? "\b" : icmp4_err[type][code] :\
                 icmp6_err[type][code] == NULL ? "\b" : icmp4_err[type][code],
                 rnr == lr ? "(dup)" : "");
    }
}



/* icmp4 packet checksum func, not include the ip header */
__u16   in_cksum( const __u16 *addr, int len )
{
    register int nleft = len;
    register const __u16 *u16_ptr = addr;
    register __u32 sum = 0;

    while( nleft > 1 )
    {
        sum += *u16_ptr++;
        nleft -= 2;
    }

    /*
     * if len is a odd number,
     * then the last byte will cale here
     */
    if( nleft > 1 )
    {
        sum += *(__u8 *) u16_ptr;
    }

    /* sum: low 16 bit add high 16 bit */
    sum = (sum & 0x0000ffff) + (sum >> 16);
    /* add the carry to sum */
    sum += (sum >> 16);

    return ~sum;
}



/* update min, max, total time */
inline void update_tv_data( const struct timeval *tv )
{
    /* maybe there a dup of the first received packet, fix it later */
    if( recvnum == 1 )
    {
        bcopy( tv, &tv_max, sizeof(struct timeval) );
        bcopy( tv, &tv_min, sizeof(struct timeval) );
        bcopy( tv, &tv_total, sizeof(struct timeval) );

        return;
    }

    /* update total time */
    tv_add ( &tv_total, tv );

    /* update min time */
    if( tv_cmp ( tv, &tv_min ) < 0 )
    {
        bcopy( tv, &tv_min, sizeof(struct timeval) );
    }
    /* update max time */
    else if( tv_cmp ( tv, &tv_max ) > 0 )
    {
        bcopy( tv, &tv_max, sizeof(struct timeval) );
    }
}



/*
 * check the current send interval time
 */
inline int check_send_interval()
{
    double t;
    struct timeval tv;

    if( seqnum == 0 )
    {
        return 0;
    }

    /* cale interval since last send */
    gettimeofday( &tv, NULL );
    tv_sub( &tv, &tv_lsend );

    t = tv2double( &tv );

    /* normal user has a limit of MIN_USR_INTERVAL,
     * if the send interval littler than MIN_USR_INTERVAL, then not send
     */
    if( uid != 0 )
    {
        if( t < MIN_USR_INTERVAL )
        {
            /* interval too short */
            return -1;
        }
        else if( t < interval )
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        /* should root check this interval */
        if( t < interval )
        {
            return -1;
        }

        return 0;
    }
}



/*
 * update the endline when the timer expired
 */
inline static  void    updata_endline()
{
    struct itimerval itv;

    getitimer( ITIMER_REAL, &itv );

    /* stop timer */
    if( stop_timer() != 0 )
    {
        /* how to do if fail stop timer ? */
        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }


    tv_sub( &itv.it_interval, &itv.it_value );

    deadline -= tv2double ( &itv.it_interval );

    if( deadline <= EPSINON )
    {
        quit( EXIT_CALL | PACKET_STATE | ERR_NONE );
    }

    /* start timer */
    if( start_timer( interval ) != 0 )
    {
        quit( EXIT_CALL | PACKET_STATE | ERR_INVPARM );
    }
}



/*
 * get addr info
 * since cannonname resolv can get by addr_ntop() call,
 * so, here do not get anything other info but address, protocol type
 */
struct addrinfo *host_addr( const char *host, 
                            int family, 
                            int socktype, 
                            int flags )
{
    int n;
    struct addrinfo hints, *res;

    bzero( &hints, sizeof(struct addrinfo) );

    hints.ai_family = family;
    hints.ai_socktype = socktype;

    hints.ai_flags = flags;
    hints.ai_protocol = 0;

//    msg_log( L_RESULT,
//             "%s: %s\n", __func__, host);

    n = getaddrinfo( host, NULL, &hints, &res );

    if( n != 0 )
    {
        msg_log( L_ERR,
                 "%s (%s): getaddrinfo fail, %s\n",
                 __func__,
                 host,
                 gai_strerror(n) );
        return NULL;
    }

    return res;
}



/* resolve a addr to its readable string and cannoname */
int addr_ntop( const void *addr, 
               char *addrstr, 
               int addr_len, 
               char *hostname, 
               int name_len, 
               int fill )
{
    int len;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
    struct sockaddr     *s;

    if( addr == NULL )
    {
        return -1;
    }

    if( addrstr != NULL && addr_len > 0 )
    {
        if( inet_ntop( pr->sa_peer->sa_family, 
                       addr, 
                       addrstr, 
                       addr_len ) == NULL )
        {
            if( fill > 0 )
            {
                if( pr->sa_peer->sa_family == AF_INET )
                {
                    strncpy( addrstr, "x.x.x.x", addr_len );
                }
                else
                {
                    strncpy( addrstr, "x::x:x:x:x", addr_len );
                }
            }
        }
    }

    if( hostname != NULL && name_len > 0 )
    {
        //bzero( &sin, sizeof(struct sockaddr_in) );
        //bzero( &sin6, sizeof(struct sockaddr_in6) );

        if( pr->sa_peer->sa_family == AF_INET )
        {
            sin.sin_family = AF_INET;
            len = sizeof(struct sockaddr_in);
            bcopy( addr, &sin.sin_addr, sizeof(struct in_addr) );
            s = (struct sockaddr *) &sin;
        }
        else
        {
            sin6.sin6_family = AF_INET6;
            len = sizeof(struct sockaddr_in6);
            bcopy( addr, &sin6.sin6_addr, sizeof(struct in6_addr) );
            s = (struct sockaddr *) &sin6;
        }

        if( getnameinfo( s,
                         len,
                         hostname, name_len,
                         NULL, 0,
                         0 ) != 0 )
        {
            if( fill > 0 )
            {
//                if( pr->sa_peer->sa_family == AF_INET )
//                {
//                    strncpy( hostname, "Unknown name", name_len );
//                }
//                else
//                {
//                    strncpy( hostname, "Unknown name", name_len );
//                }
            }
        }
    }

    return 0;
}


/* handler exit(...) call based on exit flags */
void quit( __u16 flags )
{
    int exit_status;

    if( flags & PING_ALL )
    {
        if( flags & ERR_NONE )
        {
            exit_status = 0;
        }
        else
        {
            exit_status = 1;
        }
    }
    else if( flags & PING_PART )
    {
        if( flags & ERR_NONE )
        {
            exit_status = 2;
        }
        else
        {
            exit_status = 3;
        }
    }
    /* PING_NONE */
    else
    {
        if( flags & ERR_NONE )
        {
            exit_status = 0;
        }
        else
        {
            exit_status = 4;
        }
    }

    if( flags & EXIT_CALL )
    {
        exit( exit_status );
    }
    else
    {
        _exit( exit_status );
    }
}



/* show version */
void version()
{
    msg_log( L_RESULT,
             "ping tool, %s %s build version.\n",
             __DATE__,
             __TIME__ );
}



/* show usage */
void usage()
{
    const char help_info[] =
    "Usage:\n"
    "ping [-AbBfhnqRrV]\n"
    "     [-c count] [-i interval] [-I interface] [-l preload]\n"
    "     [-s size] [-S sndbuf] [-t ttl] [-w deadline]\n"
    "     [-W timeout] [-g <source routes>] <destination>\n";

    msg_log( L_NOR, help_info );
}
