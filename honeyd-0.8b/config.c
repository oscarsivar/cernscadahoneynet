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

#include <sys/types.h>
#include <sys/param.h>

#include "config.h"
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dnet.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include <pcap.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "personality.h"
#include "template.h"
#include "subsystem.h"
#include "condition.h"
#include "interface.h"
#include "parser.h"
#include "ethernet.h"
#include "arp.h"

struct templtree templates;

int
templ_compare(struct template *a, struct template *b)
{
	return (strcmp(a->name, b->name));
}

SPLAY_GENERATE(templtree, template, node, templ_compare);

int
port_compare(struct port *a, struct port *b)
{
	int diff;

	diff = a->proto - b->proto;
	if (diff)
		return (diff);

	return ((int)a->number - (int)b->number);
}

SPLAY_PROTOTYPE(porttree, port, node, port_compare);

SPLAY_GENERATE(porttree, port, node, port_compare);

void
config_init(void)
{
	SPLAY_INIT(&templates);
}

void
config_read(char *config)
{
	FILE *fp;

	if ((fp = fopen(config, "r")) == NULL)
		err(1, "fopen(%s)", config);
	if (parse_configuration(fp, config) == -1)
		errx(1, "parsing configuration file failed");

	fclose(fp);
}

struct template *
template_find(const char *name)
{
	struct template tmp;

	tmp.name = (char *)name;
	return (SPLAY_FIND(templtree, &templates, &tmp));
}

/*
 * Checks if condition for each template in the list is matched.
 * Return the first template that we match.
 */

struct template *
template_dynamic(const struct template *tmpl, const struct ip_hdr *ip,
    u_short iplen)
{
	struct template *save = NULL;
	struct condition *cond;

	TAILQ_FOREACH(cond, &tmpl->dynamic, next) {
		if (save == NULL)
			save = cond->tmpl;

		/* See if we match this template and return it on success */
		if (cond->match == NULL ||
		    cond->match(cond->tmpl, ip, iplen, cond->match_arg))
			return (cond->tmpl);
	}

	/* We need to return something, so return the first non-NULL */
	return (save);
}

struct template *
template_find_best(const char *addr, const struct ip_hdr *ip, u_short iplen)
{
	struct template *tmpl;

	tmpl = template_find(addr);
	if (tmpl == NULL)
		tmpl = template_find("default");
	
	if (tmpl != NULL && tmpl->flags & TEMPLATE_DYNAMIC)
		tmpl = template_dynamic(tmpl, ip, iplen);

	return (tmpl);
}

struct template *
template_create(const char *name)
{
	struct template *tmpl;

	if (template_find(name))
		return (NULL);

	if ((tmpl = calloc(1, sizeof(struct template))) == NULL)
		err(1, "%s: calloc", __func__);

	tmpl->name = strdup(name);

	/* UDP ports are closed by default */
	tmpl->udp.status = PORT_RESET;

	SPLAY_INIT(&tmpl->ports);
	SPLAY_INSERT(templtree, &templates, tmpl);

	/* Configured subsystems */
	TAILQ_INIT(&tmpl->subsystems);
	TAILQ_INIT(&tmpl->dynamic);

	/* Crank ref counter */
	tmpl->refcnt++;

	return (tmpl);
}

/* Removes all configured templates from the system, so that the
 * configuration file can be re-read.
 */

void
template_free_all(void)
{
	struct template *tmpl;

	while ((tmpl = SPLAY_ROOT(&templates)) != NULL) {
		SPLAY_REMOVE(templtree, &templates, tmpl);
		template_free(tmpl);
	}
}

/* Remove a template from the system */

void
template_deallocate(struct template *tmpl)
{
	struct condition *cond;
	struct port *port;

	/* Remove ourselves from the searchable index */
	if (template_find(tmpl->name) == tmpl)
		SPLAY_REMOVE(templtree, &templates, tmpl);

	/* Free conditions for dynamic templates */
	for (cond = TAILQ_FIRST(&tmpl->dynamic); cond != NULL;
	    cond = TAILQ_FIRST(&tmpl->dynamic)) {
		TAILQ_REMOVE(&tmpl->dynamic, cond, next);

		template_free(cond->tmpl);
		if (cond->match_arg)
			free(cond->match_arg);
		free(cond);
	}
	
	/* Remove ports from template */
	while ((port = SPLAY_ROOT(&tmpl->ports)) != NULL)
		port_free(tmpl, port);

	if (tmpl->person != NULL)
		personality_declone(tmpl->person);

	if (tmpl->ethernet_addr != NULL) {
		struct arp_req *req = arp_find(tmpl->ethernet_addr);
		arp_free(req);
		free(tmpl->ethernet_addr);
	}

	free(tmpl->name);
	free(tmpl);
}

struct port *
port_find(struct template *tmpl, int proto, int number)
{
	struct port tmpport;
	
	tmpport.proto = proto;
	tmpport.number = number;
	
	return (SPLAY_FIND(porttree, &tmpl->ports, &tmpport));
}

void
port_action_clone(struct action *dst, const struct action *src)
{
	*dst = *src;
	if (src->action) {
		dst->action = strdup(src->action);
		if (dst->action == NULL)
			err(1, "%s: strdup", __func__);
	}

	if (src->aitop != NULL) {
		struct addrinfo *ai = src->aitop;
		char addr[NI_MAXHOST];
		char port[NI_MAXSERV];
		short nport;

		if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			addr, sizeof(addr), port, sizeof(port),
			NI_NUMERICHOST|NI_NUMERICSERV) != 0)
			err(1, "%s: getnameinfo", __func__);
		nport = atoi(port);
		dst->aitop = cmd_proxy_getinfo(addr, ai->ai_socktype, nport);
		if (dst->aitop == NULL)
			errx(1, "%s: cmd_proxy_getinfo failed", __func__);
	}
}

void
port_free(struct template *tmpl, struct port *port)
{
	SPLAY_REMOVE(porttree, &tmpl->ports, port);

	if (port->sub_conport != NULL) {
		/* Back pointer to connection object.
		 * It allows us to remove the reference to this object
		 * in the connection.
		 * However, at this point we really need to tear down
		 * that connection, too.
		 */
		*port->sub_conport = NULL;
	}

	if (port->sub != NULL)
		TAILQ_REMOVE(&port->sub->ports, port, next);
	if (port->sub_fd != -1)
		close(port->sub_fd);
	if (port->action.action != NULL)
		free (port->action.action);
	if (port->action.aitop != NULL)
		freeaddrinfo(port->action.aitop);
	free(port);
}

struct port *
port_insert(struct template *tmpl, int proto, int number,
    struct action *action)
{
	struct port *port, tmpport;
	
	tmpport.proto = proto;
	tmpport.number = number;
	
	if (SPLAY_FIND(porttree, &tmpl->ports, &tmpport) != NULL)
		return (NULL);
	
	if ((port = calloc(1, sizeof(struct port))) == NULL)
		err(1, "%s: calloc", __func__);

	port->sub = NULL;
	port->sub_fd = -1;
	port->proto = proto;
	port->number = number;
	port_action_clone(&port->action, action);
	    
	SPLAY_INSERT(porttree, &tmpl->ports, port);

	return (port);
}

/* Create a random port in a certain range */

struct port *
port_random(struct template *tmpl, int proto, struct action *action,
    int min, int max)
{
	extern rand_t *honeyd_rand;
	struct port *port = NULL;
	int count = 100;
	int number;

	while (count-- && port == NULL) {
		number = rand_uint16(honeyd_rand) % (max - min) + min;
		port = port_insert(tmpl, proto, number, action);
	}

	return (port);
}

int
template_add(struct template *tmpl, int proto, int number,
    struct action *action)
{
	return (port_insert(tmpl, proto, number, action) == NULL ? -1 : 0);
}

void
template_insert_subsystem(struct template *tmpl, struct subsystem *sub)
{
	struct subsystem_container *container;

	if ((container = malloc(sizeof(struct subsystem_container))) == NULL)
		err(1, "%s: malloc", __func__);

	container->sub = sub;
	TAILQ_INSERT_TAIL(&tmpl->subsystems, container, next);
}

/* This function is slow, but should only called on SIGHUP */

void
template_remove_subsystem(struct template *tmpl, struct subsystem *sub)
{
	struct subsystem_container *container;

	TAILQ_FOREACH(container, &tmpl->subsystems, next) {
		if (container->sub == sub)
			break;
	}

	if (container == NULL)
		errx(1, "%s: could not remove subsystem %p from %s",
		    sub, tmpl->name);

	TAILQ_REMOVE(&tmpl->subsystems, container, next);

	free(container);
}

struct template *
template_clone(const char *newname, const struct template *tmpl, int start)
{
	struct subsystem_container *container;
	struct condition *condition;
	struct template *newtmpl;
	struct port *port;
	struct addr addr;
	char *argv[4];
	int isipaddr = 0;

	if ((newtmpl = template_create(newname)) == NULL)
		return (NULL);

	SPLAY_FOREACH(port, porttree, (struct porttree *)&tmpl->ports) {
		if (port_insert(newtmpl, port->proto, port->number,
			&port->action) == NULL)
			return (NULL);
	}

	if (tmpl->person)
		newtmpl->person = personality_clone(tmpl->person);

	/* Keeps track of the type of template */
	isipaddr = addr_aton(newtmpl->name, &addr) != -1;

	if (tmpl->ethernet_addr) {
		newtmpl->ethernet_addr = ethernetcode_clone(tmpl->ethernet_addr);
		/* 
		 * This template wants to have its own ethernet address,
		 * so we need to register it with our arp code.
		 */
		if (isipaddr) {
			struct arp_req *req;

			newtmpl->inter = interface_find_responsible(&addr);
			if (newtmpl->inter == NULL)
				errx(1, "%s: cannot find interface");

			/* Register this mac address as our own */
			req = arp_new(newtmpl->inter, NULL, NULL, &addr,
			    newtmpl->ethernet_addr);
			if (req == NULL)
				errx(1, "%s: cannot create arp entry");

			req->flags |= ARP_INTERNAL;
		}
	}

	port_action_clone(&newtmpl->tcp, &tmpl->tcp);
	port_action_clone(&newtmpl->udp, &tmpl->udp);
	port_action_clone(&newtmpl->icmp, &tmpl->icmp);

	newtmpl->timestamp = tmpl->timestamp;
	newtmpl->uid = tmpl->uid;
	newtmpl->gid = tmpl->gid;
	newtmpl->drop_inrate = tmpl->drop_inrate;
	newtmpl->drop_synrate = tmpl->drop_synrate;
	newtmpl->flags = tmpl->flags;

	/* Clone dynamics */
	TAILQ_FOREACH(condition, &tmpl->dynamic, next) {
		if (template_insert_dynamic(newtmpl,
			condition->tmpl, condition) == -1)
			warn("%s: couldn't insert dynamic cond %s into %s",
			    condition->tmpl->name, tmpl->name);
	}

	/* Clone subsystems */
	TAILQ_FOREACH(container, &tmpl->subsystems, next) {
		struct subsystem *sub = container->sub;

		/* 
		 * Create a new subsystem structure only if the
		 * subsystem has not been specified as shared in the
		 * configuration.
		 */
		if (!sub->shared) {
			template_subsystem(newtmpl, sub->cmdstring, start, 0);
			continue;
		}

		/* Otherwise, just create references */
		TAILQ_INSERT_TAIL(&sub->templates, template_ref(newtmpl),next);

		if (isipaddr)
			SPLAY_INSERT(subtmpltree, &sub->root,
			    template_ref(newtmpl));

		template_insert_subsystem(newtmpl, sub);
	}

	/* Start subsystems if we are the master template for a subsystem */
	if (!start)
		return (newtmpl);

	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[3] = NULL;

	/* Start background processes */
	TAILQ_FOREACH(container, &newtmpl->subsystems, next) {
		struct subsystem *sub = container->sub;

		/* Has the subsystem started already? */
		if (sub->cmd.pid != -1)
			continue;

		argv[2] = sub->cmdstring;
		if (cmd_subsystem(newtmpl, sub, "/bin/sh", argv) == -1)
			errx(1, "%s: can not start subsystem \"%s\" for %s",
			    sub->cmdstring, newtmpl->name);
	}

	return (newtmpl);
}

int
template_subsystem(struct template *tmpl, char *subsystem, int isaddr, int shared)
{
	struct subsystem *sub;
	
	if ((sub = calloc(1, sizeof(struct subsystem))) == NULL)
		err(1, "%s: calloc", __func__);

	if ((sub->cmdstring = strdup(subsystem)) == NULL)
		err(1, "%s: strdup", __func__);

	/* Initializes subsystem data structures */
	TAILQ_INIT(&sub->ports);
	SPLAY_INIT(&sub->root);
	TAILQ_INIT(&sub->templates);

	TAILQ_INSERT_TAIL(&sub->templates, template_ref(tmpl), next);

	/*
	 * Only make this template available to the subsystem if it is
	 * an internet address.
	 */
	if (isaddr)
		SPLAY_INSERT(subtmpltree, &sub->root, template_ref(tmpl));
	sub->cmd.pid = -1;
	sub->shared = shared;

	template_insert_subsystem(tmpl, sub);

	return (0);
}

void
template_subsystem_free(struct subsystem *sub)
{
	struct template *tmpl;
	struct port *port;

	for (port = TAILQ_FIRST(&sub->ports); port;
	    port = TAILQ_FIRST(&sub->ports)) {
		
		/* Free all ports for this subsystem */
		port_free(port->subtmpl, port);
	}
		
	/* 
	 * As we are removing all templates for this subsystem, we
	 * actually do not need to remove them from the Splay.
	 */
	TAILQ_FOREACH(tmpl, &sub->templates, next) {
		template_remove_subsystem(tmpl, sub);

		template_free(tmpl);
	}

	free(sub->cmdstring);
	free(sub);
}

/* 
 * Inserts a new conditional template into a dynamic template.
 * The condition gets cloned in the process.
 */

int
template_insert_dynamic(struct template *tmpl, struct template *child,
    struct condition *condition)
{
	char newname[1024];
	struct condition *cond;

	if ((cond = calloc(1, sizeof(struct condition))) == NULL)
		err(1, "%s: calloc", __func__);

	if (condition != NULL)
		*cond = *condition;

	/* Con up a new template name */
	snprintf(newname, sizeof(newname), "%s_%s", tmpl->name, child->name);
	if ((cond->tmpl = template_clone(newname, child, 0)) == NULL) {
		fprintf(stderr, "Failed to clone %s from %s\n",
		    newname, child->name);
		free(cond);
		return (-1);
	}

	TAILQ_INSERT_TAIL(&tmpl->dynamic, cond, next);

	/* Do we need to copy the match arg, too? */
	if (condition == NULL || condition->match_arg == NULL)
		return (0);

	if ((cond->match_arg = malloc(cond->match_arglen)) == NULL)
		err(1, "%s: malloc", __func__);

	memcpy(cond->match_arg, condition->match_arg, cond->match_arglen);

	return (0);
}
