/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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
#ifndef _SUBSYSTEM_H_
#define _SUBSYSTEM_H_

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
struct sockaddr_storage {
        u_char iamasuckyoperatingsystem[256];
};
#endif

/* Subsystem state */

struct subsystem {
	TAILQ_ENTRY(subsystem) next;

	SPLAY_HEAD(subtmpltree, template) root;	/* back pointers: IPv4 name */
	TAILQ_HEAD(templateq, template) templates; /* all templates */
	char *cmdstring;

	struct command cmd;

	int shared;

	TAILQ_HEAD(portqueue, port) ports;	/* list of configured ports */
};

SPLAY_PROTOTYPE(subtmpltree, template, sub_node, templ_compare);

#define SUBSYSTEM_MAGICFD	4

enum subcmd { 
	BIND=1, LISTEN, CLOSE, CONNECT, SENDTO
};

struct subsystem_command {
	int domain;
	int type;
	int protocol;
	enum subcmd command;

	/* Local address */
	socklen_t len;
	struct sockaddr_storage sockaddr;

	/* Remote address */
	socklen_t rlen;
	struct sockaddr_storage rsockaddr;
};

#endif
