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

#ifndef _TEMPLATE_
#define _TEMPLATE_

#include <assert.h>

struct personality;
struct subsystem;
struct ip_hdr;

struct subsystem_container {
	TAILQ_ENTRY(subsystem_container) next;

	struct subsystem *sub;
};


struct condition;
struct template {
	SPLAY_ENTRY(template) node;
	SPLAY_ENTRY(template) sub_node;		/* for subsystem sharing */
	TAILQ_ENTRY(template) next;		/* for subsystem sharing */

	char *name;

	struct porttree ports;

	struct action icmp;
	struct action tcp;
	struct action udp;

	struct personality *person;

	int id;
	uint32_t seq;
	int seqcalls;
	uint32_t timestamp;
	struct timeval tv;

	uint16_t drop_inrate;
	uint16_t drop_synrate;

	uid_t uid;
	gid_t gid;

	TAILQ_HEAD(subsysqueue, subsystem_container) subsystems;

	/* Condition on which this template is activated */
	TAILQ_HEAD(conditionqueue, condition) dynamic;
	
	/* Special handling for templates */
	int flags;
	struct interface *inter;

	/* Set when we are to use this ethernet_address */
	struct addr *ethernet_addr;

	/* Reference counter */
	uint16_t refcnt;
};

#define TEMPLATE_EXTERNAL	0x0001	/* Real machine on external network */
#define TEMPLATE_DYNAMIC	0x0002	/* Pointer to templates */

/* Required to access template from different source files */
SPLAY_HEAD(templtree, template);
int templ_compare(struct template *, struct template *);
SPLAY_PROTOTYPE(templtree, template, node, templ_compare);

struct template *template_create(const char *);
int template_add(struct template *, int, int, struct action *);
int template_subsystem(struct template *, char *, int, int);
struct template *template_clone(const char *, const struct template *, int);
struct template *template_find(const char *);
struct template *template_find_best(const char *, const struct ip_hdr *,
    u_short);

int template_insert_dynamic(struct template *, struct template *,
    struct condition *);

void template_free_all(void);
void template_subsystem_free(struct subsystem *);

int templ_compare(struct template *, struct template *);

void template_deallocate(struct template *);

#define template_free(x)	do {					\
	if ((x) == NULL)						\
		break;							\
	/* Decrease ref counter */					\
	(x)->refcnt--;							\
	if ((x)->refcnt <= 0)						\
		template_deallocate(x);					\
} while (0)

static __inline struct template *
template_ref(struct template *tmpl)
{
	if (tmpl != NULL) {
		tmpl->refcnt++;
		assert(tmpl->refcnt);
	}
	return (tmpl);
}

#endif /* _TEMPLATE_ */
