/***************************************************************************
 *            defines.h
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


#ifndef _DEFINES_H_
#define _DEFINES_H_

/* feature_test_macros */
#define _GNU_SOURCE     /* enable gnu libc support */
#define _ISOC99_SOURCE  /* enable C99 support */



#include <netinet/in.h>



/* for attribute mocro function */
#ifdef _GNU_SOURCE
    #define ATTR(x) __attribute__((x))
#else
    #define ATTR(x)
#endif


/* define some data type */

/* not sure here, so use what "netinet/in.h" header defined */
typedef uint32_t          __u32;
typedef unsigned short    __u16;
typedef unsigned char     __u8;


/* for double & float */
#define EPSINON 0.000001


/* msg level */
#define L_NOR       1
#define L_RESULT    2
#define L_ERR       3


/*
 * code for exit
 */

/* the count ping success */
#define PING_NONE       0x0001
#define PING_PART       0x0002
#define PING_ALL        0x0004

/* error code */
#define ERR_NONE        0x0010
#define ERR_INVPARM     0x0020
#define ERR_SYSTEM      0x0040
#define ERR_PERMISSION  0x0080

/* _exit(...) or exit(...)  */
#define EXIT_CALL       0x0100
#define _EXIT_CALL      0x0200


/* max msg length */
#define MAX_STRING_LEN  4089


/* time convert */
#define SEC2USEC    1000000
#define SEC2MSEC    1000
#define MSEC2USEC   1000



#endif    /* _DEFINE_H_ */
