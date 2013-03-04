/***************************************************************************
 *            misc.c
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>
#include <ctype.h>


/*
 * declare again to ensure the msg_log format check in current code file
 */
int msg_log( int , const char *, ... ) ATTR(format(printf, 2, 3));



/* msg logger */
int msg_log( int level, const char *format, ... )
{
    char buf[MAX_STRING_LEN];
    va_list args;

    va_start( args, format );

    /* may be truncated if buffer is too small */
    vsnprintf( buf, sizeof( buf ), format, args );
    va_end( args );

    /* process diff based on level */
    if( level > 0 )
    {
        fprintf( stderr, "%s", buf );
    }

    return 0;
}



/* time in param 1 sub the time in param 2, then store result in param 1 */
inline void tv_sub( struct timeval *tv1, const struct timeval *tv2 )
{
    if( (tv1->tv_usec -= tv2->tv_usec) < 0 )
    {
        tv1->tv_usec += SEC2USEC;
        tv1->tv_sec--;
    }

    tv1->tv_sec -= tv2->tv_sec;
}



/* add two timeval struct value */
inline void tv_add( struct timeval *tv1, const struct timeval *tv2 )
{
    tv1->tv_sec -= tv2->tv_sec;

    if( (tv1->tv_usec += tv2->tv_usec) > SEC2USEC )
    {
        tv1->tv_usec -= SEC2USEC;
        tv1->tv_sec ++;
    }
}



/*
 * cmpare tv1 and tv2
 *
 * return:
 *  -1  tv1 is before tv2
 *  0   tv1 equal to tv2
 *  1   tv1 is after tv2
 */
inline int  tv_cmp( const struct timeval *tv1, const struct timeval *tv2 )
{
    if( tv1->tv_sec > tv2->tv_sec )
    {
        return 1;
    }
    else if( tv1->tv_sec == tv2->tv_sec )
    {
        if( tv1->tv_usec > tv2->tv_usec )
        {
            return 1;
        }
        else if( tv1->tv_usec < tv2->tv_usec )
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
        return -1;
    }
}



/* convert a double time value in ms to a timeval struct value */
inline void double2tv( struct timeval *tv, double dtime )
{
    if( dtime <= EPSINON )
    {
        tv->tv_sec = 0;
        tv->tv_usec = 0;

        return;
    }

    tv->tv_sec = (time_t) dtime;

    if( tv->tv_sec > 0 )
    {
        tv->tv_usec = ( (long)(dtime * 1000) % (tv->tv_sec * 1000)) * SEC2USEC;
    }
    else
    {
        tv->tv_usec = dtime * SEC2USEC;
    }
}



/* struct timeval value convert to a double value in ms */
inline double tv2double( const struct timeval *tv )
{
    if( tv->tv_sec < 0 || tv->tv_usec < 0 )
    {
        return 0.0;
    }

    return tv->tv_sec * SEC2MSEC + (double)tv->tv_usec / MSEC2USEC;
}



/* start timer in special interval */
int start_timer( double interval )
{
    struct itimerval itv;

    if( interval <= EPSINON )
    {
        msg_log( L_ERR,
                 "%s: timer interval is zero\n",
                 __func__);
        return -1;
    }

    double2tv( &itv.it_interval, interval );
    bcopy( &itv.it_interval, &itv.it_value, sizeof( struct timeval ) );

    //msg_log( L_ERR, "%d.%d\n", sec, usec );

    /*
     * start a ITIMER_REAL timer.
     * ITIMER_VIRTUAL and ITIMER_PROF timer is not update its value
     * when this process is not run by CPU,
     * and if we call resvmsg then CPU queue this process in block-state,
     * until packet come and change to running -state.
     * so ITIMER_VIRTUAL and ITIMER_PROF timer will not expire when we expected
     */
    if( setitimer( ITIMER_REAL, &itv, NULL ) == -1 )
    {
        msg_log( L_ERR,
                 "%s: %s\n",
                 __func__,
                 strerror(errno) );
        return -1;
    }

    return 0;
}



/* stop the timer */
int stop_timer()
{
    struct itimerval itv;

    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec = 0;
    itv.it_value.tv_usec = 0;

    if( setitimer( ITIMER_REAL, &itv, NULL ) == -1 )
    {
        msg_log( L_ERR,
                 "%s: %s\n",
                 __func__,
                 strerror(errno) );
        return -1;
    }

    return 0;
}



/* print the packet in hex and readable char for debugging */
void print_packet( const char *buf, int len )
{
    __u8 *end = (__u8 *)buf + len;
    __u8 *p8 = (__u8 *) buf;

    /* hex */
    while( p8 < end )
    {
        msg_log( L_NOR, "%.2x ", *p8++ );
    }

    msg_log( L_NOR, "\n" );


    p8 = (__u8 *) buf;

    /* readable char */
    while( p8 < end )
    {
        if( isprint(*p8) )
        {
            msg_log( L_NOR, "%c", *p8++ );
        }
        else
        {
            msg_log( L_NOR, "." );
            p8++;
        }
    }

    msg_log( L_NOR, "\n" );
}



/*
 * return 1 in special percent probability,
 * for simulating packet lost
 */
int lost_some( int percent )
{
    int rand;

    if( percent <= 0 )
    {
        return 0;
    }

    /* 0 ~ 99 */
    rand = (int)random() % 100;

    if( rand < percent )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

