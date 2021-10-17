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

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>
#include <sys/queue.h>

#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <dnet.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "subsystem.h"
#include "fdpass.h"

ssize_t atomicio(ssize_t (*)(), int, void *, size_t);


/* Store referencing templates in tree */
SPLAY_GENERATE(subtmpltree, template, sub_node, templ_compare);

void subsystem_read(int, short, void *);
void subsystem_write(int, short, void *);

struct callback subsystem_cb = {
	subsystem_read, subsystem_write, NULL, NULL
};

/* Determine if the socket information is valid */

#define SOCKET_REMOTE		0
#define SOCKET_LOCAL		1
#define SOCKET_MAYBELOCAL	2

int
subsystem_socket(struct subsystem_command *cmd, int local,
    char *ip, size_t iplen, u_short *port, int *proto)
{
	struct sockaddr_in *si;
	struct addr src;
	socklen_t len;

	si = (struct sockaddr_in *)(local ? &cmd->sockaddr : &cmd->rsockaddr);
	len = local ? cmd->len : cmd->rlen;

	/* Only IPv4 TCP or UDP is allowed.  No raw sockets or such */
	if (si->sin_family != AF_INET || cmd->domain != AF_INET ||
	    !(cmd->type == SOCK_DGRAM || cmd->type == SOCK_STREAM) ||
	    len != sizeof(struct sockaddr_in)) {
		if (local == SOCKET_LOCAL)
			return (-1);
		memset(&cmd->sockaddr, 0, sizeof(cmd->sockaddr));
	}

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &si->sin_addr.s_addr,
	    IP_ADDR_LEN);
	addr_ntop(&src, ip, iplen);

	*port = ntohs(si->sin_port);
	*proto = cmd->type == SOCK_DGRAM ? IP_PROTO_UDP : IP_PROTO_TCP;

	return (0);
}

void
subsystem_cleanup(struct subsystem *sub)
{
	syslog(LOG_INFO, "Subsystem \"%s\" died", sub->cmdstring);

	/* XXX - do proper cleanup here */
	template_subsystem_free(sub);
}

void
subsystem_readyport(struct port *port, struct subsystem *sub,
    struct template *tmpl)
{
	port->sub = sub;
	port->subtmpl = tmpl;
	port->sub_fd = -1;

	TAILQ_INSERT_TAIL(&sub->ports, port, next);
}

int
subsystem_bind(struct template *tmpl, struct subsystem *sub,
    int proto, u_short port)
{
	struct port *sub_port;
	struct action action;

	/* Setup port type */
	memset(&action, 0, sizeof(action));
	action.status = PORT_RESERVED;

	sub_port = port_insert(tmpl, proto, port, &action);
	if (sub_port == NULL)
		return (-1);
		
	/* Set up necessary port information */
	subsystem_readyport(sub_port, sub, tmpl);

	syslog(LOG_DEBUG, "Subsytem \"%s\" binds %s:%d",
	    sub->cmdstring, tmpl->name, port);

	return (0);
}

int
subsystem_listen(struct port *sub_port, char *ip, int nfd)
{
	syslog(LOG_DEBUG, "Listen: %s:%d -> fd %d", 
	    ip, sub_port->number, nfd);

	/* We use this fd to notify the other side */
	sub_port->sub_fd = dup(nfd);
	if (sub_port->sub_fd == -1)
		return (-1);
	sub_port->sub_islisten = 1;
			
	/* Enable this port */
	sub_port->action.status = PORT_SUBSYSTEM;

	return (0);
}

void
subsystem_read(int fd, short what, void *arg)
{
	struct subsystem *sub = arg;
	struct subsystem_command cmd;
	struct sockaddr_in *si = (struct sockaddr_in *)&cmd.sockaddr;
	char asrc[24], adst[24];
	u_short port;
	int proto;
	char res = -1;

	if (atomicio(read, fd, &cmd, sizeof(cmd)) != sizeof(cmd)) {
		subsystem_cleanup(sub);
		return;
	}

	switch (cmd.command) {
	case BIND: {
		struct template *tmpl, tmp;
	
		/* Check address family */
		if (subsystem_socket(&cmd, SOCKET_LOCAL, asrc, sizeof(asrc),
			&port, &proto) == -1)
			goto out;

		/* See if it tries to bind an address that we know */
		if (si->sin_addr.s_addr == IP_ADDR_ANY) {
			/* Bind to all associated templates */
			SPLAY_FOREACH(tmpl, subtmpltree, &sub->root) {
				if ((res = subsystem_bind(tmpl, sub, proto,
					 port)) == -1)
					break;
			}
			goto out;
		}

		/* See if we can find a good template */
		tmp.name = asrc;
		if ((tmpl = SPLAY_FIND(subtmpltree, &sub->root,
			 &tmp)) == NULL) {
			tmpl = SPLAY_ROOT(&sub->root);
			syslog(LOG_WARNING,
			    "Subsystem %s on %s attempts illegal bind %s:%d",
			    sub->cmdstring, tmpl->name, asrc, port);
			goto out;
		}

		res = subsystem_bind(tmpl, sub, proto, port);
		break;
	}

	case LISTEN: {
		struct template *tmpl;
		struct port *sub_port = NULL;
		int nfd;

		/* Check address family */
		if (subsystem_socket(&cmd, SOCKET_LOCAL, asrc, sizeof(asrc),
			&port, &proto) == -1) {
			syslog(LOG_WARNING, "%s: listen bad socket", __func__);
			goto out;
		}

		if (strcmp(asrc, "0.0.0.0") != 0) {
			struct template tmp;
			tmp.name = asrc;
			tmpl = SPLAY_FIND(subtmpltree, &sub->root, &tmp);
		} else {
			tmpl = SPLAY_ROOT(&sub->root);
		}
		if (tmpl != NULL)
			sub_port = port_find(tmpl, proto, port);
		if (sub_port == NULL) {
			syslog(LOG_WARNING, "%s: proto %d port %d not bound",
			    __func__, proto, port);
			goto out;
		}

		res = 0;
		atomicio(write, fd, &res, 1);
		res = -1;

		/* Repeat until we get a result */
		while ((nfd = receive_fd(fd, NULL, NULL)) == -1) {
			if (errno != EAGAIN)
				break;
		}

		if (nfd == -1) {
			syslog(LOG_WARNING, "%s: no file descriptor",__func__);
			goto out;
		}

		if (strcmp(asrc, "0.0.0.0") != 0) {
			subsystem_listen(sub_port, asrc, nfd);
		} else {
			/* 
			 * Subsystem sharing means that we need to
			 * listen to all templates
			 */
			SPLAY_FOREACH(tmpl, subtmpltree, &sub->root) {
				sub_port = port_find(tmpl, proto, port);
				if (sub_port == NULL)
					errx(1, "%s: no proto %d port %d",
					    __func__, proto, port);
				if (subsystem_listen(sub_port, asrc,
					nfd) == -1)
					break;
			}
		}

		/* Close this file descriptor */
		close(nfd);
		
		res = 0;
		break;
	}

	case CLOSE: {
		struct template *tmpl = NULL;
		struct port *sub_port;

		/* Check address family */
		if (subsystem_socket(&cmd, SOCKET_LOCAL, asrc, sizeof(asrc),
			&port, &proto) == -1)
			goto out;

		syslog(LOG_DEBUG, "Close: %s:%d", asrc, port);
		if (strcmp(asrc, "0.0.0.0") != 0) {
			struct template tmp;
			tmp.name = asrc;
			tmpl = SPLAY_FIND(subtmpltree, &sub->root, &tmp);
			if (tmpl == NULL)
				goto out;
			sub_port = port_find(tmpl, proto, port);
			if (sub_port == NULL || sub_port->sub != sub)
				goto out;
			
			port_free(tmpl, sub_port);
		} else {
			SPLAY_FOREACH(tmpl, subtmpltree, &sub->root) {
				/* XXX - only bound port */
				sub_port = port_find(tmpl, proto, port);
				if (sub_port == NULL || sub_port->sub != sub)
					goto out;
				
				port_free(tmpl, sub_port);
			}
		}
		break;
	}

	case CONNECT: {
		struct template *tmpl;
		struct port *sub_port;
		struct action action;
		struct addr src, dst;
		struct ip_hdr ip;

		/* Check remote address family */
		if (subsystem_socket(&cmd, SOCKET_MAYBELOCAL,
			asrc, sizeof(asrc), &port, &proto) == -1)
			goto out;
		if (subsystem_socket(&cmd, SOCKET_REMOTE, adst, sizeof(asrc),
			&port, &proto) == -1)
			goto out;
		
		/* Find appropriate template */
		if (strcmp(asrc, "0.0.0.0") != 0) {
			struct template tmp;
			tmp.name = asrc;
			tmpl = SPLAY_FIND(subtmpltree, &sub->root, &tmp);
			if (tmpl == NULL)
				errx(1, "%s: source address %s not found",
				    __func__, asrc);
		} else
			tmpl = SPLAY_ROOT(&sub->root);

		syslog(LOG_DEBUG, "Connect: %s %s->%s:%d",
		    proto == IP_PROTO_UDP ? "udp" : "tcp",
		    tmpl->name, adst, port);

		if (addr_aton(tmpl->name, &src) == -1)
			goto out;
		if (addr_aton(adst, &dst) == -1)
			goto out;

		memset(&action, 0, sizeof(action));
		action.status = PORT_RESERVED;

		sub_port = port_random(tmpl, proto, &action, 1024, 49151);
		if (sub_port == NULL)
			goto out;
		syslog(LOG_DEBUG, "Connect: allocated port %d",
		    sub_port->number);

		subsystem_readyport(sub_port, sub, tmpl);

		/* The remote side is the source */
		ip.ip_src = dst.addr_ip;
		ip.ip_dst = src.addr_ip;

		/* Try to setup a TCP connection */
		if (proto == IP_PROTO_TCP) {
			struct tcp_con *con;
			struct tcp_hdr tcp;
			int nfd;

			tcp.th_sport = htons(port);
			tcp.th_dport = htons(sub_port->number);

			if ((con = tcp_new(&ip, &tcp, 1)) == NULL)
				goto out;
			con->tmpl = template_ref(tmpl);

			/* Cross notify */
			con->port = sub_port;
			sub_port->sub_conport = &con->port;

			/* Confirm success of this phase */
			res = 0;
			atomicio(write, fd, &res, 1);
			
			/* Now get the control fd */
			while ((nfd = receive_fd(fd, NULL, NULL)) == -1) {
				if (errno != EAGAIN) {
					tcp_free(con);
					goto out;
				}
			}
			sub_port->sub_fd = nfd;

			/* Confirm success again */
			res = 0;
			atomicio(write, nfd, &res, 1);
			
			/* Send out the SYN packet */
			con->state = TCP_STATE_SYN_SENT;
			tcp_send(con, TH_SYN, NULL, 0);
			con->snd_una++;

			con->retrans_time = 1;
			generic_timeout(&con->retrans_timeout, con->retrans_time);
			goto reschedule;
		} else if (proto == IP_PROTO_UDP) {
			struct udp_con *con;
			struct udp_hdr udp;

			/* The remote side is the source */
			udp.uh_sport = htons(port);
			udp.uh_dport = htons(sub_port->number);

			if ((con = udp_new(&ip, &udp, 1)) == NULL)
				goto out;
			con->tmpl = template_ref(tmpl);
			
			/* Cross notify */
			con->port = sub_port;
			sub_port->sub_conport = &con->port;

			/* Confirm success of this phase */
			res = 0;
			atomicio(write, fd, &res, 1);

			/* Connect our system to the subsystem */
			cmd_subsystem_localconnect(&con->conhdr, &con->cmd,
			    sub_port, con);
			goto reschedule;
		}
	}
	default:
		break;
	}

 out:
	atomicio(write, fd, &res, 1);
 reschedule:
	/* Reschedule read */
	event_add(&sub->cmd.pread, NULL);
}

void
subsystem_write(int fd, short what, void *arg)
{
	/* Nothing */
}
