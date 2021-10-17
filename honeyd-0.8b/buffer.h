/*
 * Copyright (c) 2001, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _BUFFER_H_
#define _BUFFER_H_

struct buffer {
	u_char *buffer;

	size_t totallen;
	size_t off;
};

#define BUFFER_LENGTH(x)	(x)->off

struct buffer *buffer_new(void);
void buffer_free(struct buffer *);
void buffer_add(struct buffer *, u_char *, size_t);
void buffer_add_buffer(struct buffer *, struct buffer *);
int buffer_add_printf(struct buffer *, char *fmt, ...);
void buffer_drain(struct buffer *, size_t);
int buffer_write(struct buffer *, int);
int buffer_read(struct buffer *, int, int);
u_char *buffer_find(struct buffer *, u_char *, size_t);

#endif /* _BUFFER_H */
