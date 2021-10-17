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

/*
 * Copyright (c) 1999, 2000 Dug Song <dugsong@monkey.org>
 * All rights reserved, all wrongs reversed.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <pcap.h>
#include <dnet.h>

int
pcap_dloff(pcap_t *pd)
{
	int offset = -1;
	
	switch (pcap_datalink(pd)) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_IEEE802:
		offset = 22;
		break;
	case DLT_FDDI:
		offset = 21;
		break;
#ifdef DLT_PPP
        case DLT_PPP:
                offset = 24;
                break;
#endif
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
                offset = 16;
                break;
#endif
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		offset = 4;
		break;
	default:
		warnx("unsupported datalink type");
		break;
	}
	return (offset);
}

char *
strrpl(char *str, size_t size, char *match, char *value)
{
	char *p, *e;
	int len, rlen;

	p = str;
	e = p + strlen(p);
	len = strlen(match);

	/* Try to match against the variable */
	while ((p = strchr(p, match[0])) != NULL) {
		if (!strncmp(p, match, len) && !isalnum(p[len]))
			break;
		p += len;

		if (p >= e)
			return (NULL);
		    
	}

	if (p == NULL)
		return (NULL);

	rlen = strlen(value);

	if (strlen(str) - len + rlen > size)
		return (NULL);

	memmove(p + rlen, p + len, strlen(p + len) + 1);
	memcpy(p, value, rlen);

	return (p);
}

/*
 * Checks if <addr> is contained in the network specified by <net>
 */

int
addr_contained(struct addr *net, struct addr *addr)
{
	struct addr tmp;

	tmp = *net;
	tmp.addr_bits = IP_ADDR_BITS;
	if (addr_cmp(&tmp, addr) > 0)
		return (0);

	addr_bcast(net, &tmp);
	tmp.addr_bits = IP_ADDR_BITS;
	if (addr_cmp(&tmp, addr) < 0)
		return (0);

	return (1);
}

char *
strnsep(char **line, char *delim)
{
	char *ret, *p;

	if (line == NULL)
		return (NULL);

	ret = *line;
	if (ret == NULL)
		return (NULL);

	p = strpbrk(ret, delim);
	if (p == NULL) {
		*line = NULL;
		return (ret);
	}

	*line = p + strspn(p, delim);
	*p = '\0';

	return (ret);
}

#ifndef HAVE_FGETLN
char *
fgetln(FILE *stream, size_t *len)
{
	static char buf[1024];

	if (fgets(buf, sizeof(buf), stream) == NULL)
		return (NULL);
	
	*len = strlen(buf);

	return (buf);
}
#endif
