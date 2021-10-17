/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <fcntl.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "buffer.h"

extern int debug;

struct buffer *
buffer_new(void)
{
	struct buffer *buffer;
	
	if ((buffer = calloc(1, sizeof(struct buffer))) == NULL)
		err(1, "%s: calloc", __func__);

	return (buffer);
}

void
buffer_free(struct buffer *buffer)
{
	if (buffer->buffer != NULL)
		free(buffer->buffer);
	free(buffer);
}

void
buffer_add_buffer(struct buffer *outbuf, struct buffer *inbuf)
{
	buffer_add(outbuf, inbuf->buffer, inbuf->off);
	buffer_drain(inbuf, inbuf->off);
}

int
buffer_add_printf(struct buffer *buf, char *fmt, ...)
{
	int res = -1;
	char *msg;
	va_list ap;

	va_start(ap, fmt);

	if (vasprintf(&msg, fmt, ap) == -1)
		goto end;
	
	res = strlen(msg);
	buffer_add(buf, msg, res);
	free(msg);

 end:
	va_end(ap);

	return (res);
}

void
buffer_add(struct buffer *buf, u_char *data, size_t datlen)
{
	size_t need = buf->off + datlen;

	if (buf->totallen < need) {
		if ((buf->buffer = realloc(buf->buffer, need)) == NULL)
			err(1, "%s: realloc", __func__);
		buf->totallen = need;
	}

	memcpy(buf->buffer + buf->off, data, datlen);
	buf->off += datlen;
}

void
buffer_drain(struct buffer *buf, size_t len)
{
	if (len >= buf->off) {
		buf->off = 0;
		return;
	}

	memmove(buf->buffer, buf->buffer + len, buf->off - len);
	buf->off -= len;
}

int
buffer_read(struct buffer *buffer, int fd, int howmuch)
{
	u_char inbuf[4096];
	int n;
	
	if (howmuch < 0 || howmuch > sizeof(inbuf))
		howmuch = sizeof(inbuf);

	n = read(fd, inbuf, howmuch);
	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);

	buffer_add(buffer, inbuf, n);

	return (n);
}

int
buffer_write(struct buffer *buffer, int fd)
{
	int n;

	n = write(fd, buffer->buffer, buffer->off);
	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);

	buffer_drain(buffer, n);

	return (n);
}

u_char *
buffer_find(struct buffer *buffer, u_char *what, size_t len)
{
	size_t remain = buffer->off;
	u_char *search = buffer->buffer;
	u_char *p;

	while ((p = memchr(search, *what, remain)) != NULL && remain >= len) {
		if (memcmp(p, what, len) == 0)
			return (p);

		search = p + 1;
		remain = buffer->off - (size_t)(search - buffer->buffer);
	}

	return (NULL);
}
