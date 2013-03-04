/***************************************************************************
 *            misc.h
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


#ifndef _MISC_H
#define _MISC_H


#include "defines.h"


extern int msg_log( int , const char *, ... ) ATTR(format(printf, 2, 3));

extern int start_timer( double );
extern int stop_timer();

extern void tv_sub( struct timeval *, const struct timeval * );
extern void tv_add( struct timeval *, const struct timeval * );
extern int  tv_cmp( const struct timeval *, const struct timeval * );
extern void double2tv( struct timeval *, double );
extern double tv2double( const struct timeval * );

extern int lost_some( int );

extern void print_packet( const char *, int );


#endif    /* _MISC_H */
