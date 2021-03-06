// $Id: inline.h,v 1.1 2004/09/13 17:44:49 jhewlett Exp $
#ifndef __INLINE_H__
#define __INLINE_H__

#ifdef GIDS

#ifndef IPFW
#include <libipq.h>
#include <linux/netfilter.h>
#else
#include <sys/types.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <errno.h>
#endif /* IPFW */

#include "snort.h"

typedef struct _inline_vals
{
    int drop;
    int reject;
    int replace;
    int proto;
} IV;

#ifndef IPFW
struct ipq_handle *ipqh;
#endif
IV iv;

int InitInline();
void InitInlinePostConfig(void);
#ifndef IPFW
void IpqLoop();
#else
void IpfwLoop();
#endif /* IPFW */
int InlineReject(Packet *); /* call to reject current packet */
int InlineAccept();
int InlineReplace();

#endif

int InlineMode();
int InlineDrop();  /* call to drop current packet */

#endif /* __INLINE_H__ */
