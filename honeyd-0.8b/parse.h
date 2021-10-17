#ifndef BISON_Y_TAB_H
# define BISON_Y_TAB_H

#ifndef YYSTYPE
typedef union {
	char *string;
	int number;
	struct link_drop drop;
	struct addr addr;
	struct action action;
	struct template *tmpl;
	struct personality *pers;
	struct addrinfo *ai;
	enum fragpolicy fragp;
	float floatp;
	struct condition condition;
	struct tm time;
	struct condition_time timecondition;
} yystype;
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif
# define	CREATE	257
# define	ADD	258
# define	PORT	259
# define	BIND	260
# define	CLONE	261
# define	DOT	262
# define	BLOCK	263
# define	OPEN	264
# define	RESET	265
# define	DEFAULT	266
# define	SET	267
# define	ACTION	268
# define	PERSONALITY	269
# define	RANDOM	270
# define	ANNOTATE	271
# define	NO	272
# define	FINSCAN	273
# define	FRAGMENT	274
# define	DROP	275
# define	OLD	276
# define	NEW	277
# define	COLON	278
# define	PROXY	279
# define	UPTIME	280
# define	DROPRATE	281
# define	IN	282
# define	SYN	283
# define	UID	284
# define	GID	285
# define	ROUTE	286
# define	ENTRY	287
# define	LINK	288
# define	NET	289
# define	UNREACH	290
# define	SLASH	291
# define	LATENCY	292
# define	MS	293
# define	LOSS	294
# define	BANDWIDTH	295
# define	SUBSYSTEM	296
# define	OPTION	297
# define	TO	298
# define	SHARED	299
# define	NETWORK	300
# define	TUNNEL	301
# define	TARPIT	302
# define	DYNAMIC	303
# define	USE	304
# define	IF	305
# define	OTHERWISE	306
# define	EQUAL	307
# define	SOURCE	308
# define	OS	309
# define	IP	310
# define	BETWEEN	311
# define	DELETE	312
# define	LIST	313
# define	ETHERNET	314
# define	DASH	315
# define	TIME	316
# define	INTERNAL	317
# define	STRING	318
# define	CMDSTRING	319
# define	IPSTRING	320
# define	NUMBER	321
# define	PROTO	322
# define	FLOAT	323


extern YYSTYPE yylval;

#endif /* not BISON_Y_TAB_H */
