/* A Bison parser, made from parse.y
   by GNU bison 1.35.  */

#define YYBISON 1  /* Identify Bison output.  */

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

#line 7 "parse.y"

#include <sys/types.h>

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <pcap.h>
#include <dnet.h>

#include <event.h>

#include "buffer.h"
#include "honeyd.h"
#include "personality.h"
#include "router.h"
#include "plugins_config.h"
#include "plugins.h"
#include "template.h"
#include "condition.h"
#include "interface.h"
#include "ethernet.h"
#include "pfvar.h"
#ifdef HAVE_PYTHON
#include "pyextend.h"
#endif

int hydlex(void);
int hydparse(void);
int hyderror(char *, ...);
int hydwarn(char *, ...);
int hydprintf(char *, ...);
void *hyd_scan_string(char *);
int hyd_delete_buffer(void *);

#define yylex hydlex
#define yyparse hydparse
#define yy_scan_string hyd_scan_string
#define yy_delete_buffer hyd_delete_buffer
#define yyerror hyderror
#define yywarn hydwarn
#define yyprintf hydprintf
#define yyin hydin

pf_osfp_t pfctl_get_fingerprint(const char *);
struct action *honeyd_protocol(struct template *, int);
void port_action_clone(struct action *, struct action *);

static struct buffer *buffer = NULL;
int lineno;
char *filename;
int errors = 0;
int curtype = -1;	/* Lex sets it to SOCK_STREAM or _DGRAM */


#line 106 "parse.y"
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
#ifndef YYDEBUG
# define YYDEBUG 0
#endif



#define	YYFINAL		177
#define	YYFLAG		-32768
#define	YYNTBASE	70

/* YYTRANSLATE(YYLEX) -- Bison token number corresponding to YYLEX. */
#define YYTRANSLATE(x) ((unsigned)(x) <= 323 ? yytranslate[x] : 99)

/* YYTRANSLATE[YYLEX] -- Bison token number corresponding to YYLEX. */
static const char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69
};

#if YYDEBUG
static const short yyprhs[] =
{
       0,     0,     1,     4,     7,    10,    13,    16,    19,    22,
      25,    28,    31,    34,    37,    40,    43,    49,    56,    63,
      69,    75,    79,    84,    89,    93,   100,   105,   110,   115,
     121,   127,   132,   139,   143,   147,   151,   157,   168,   177,
     182,   187,   189,   192,   195,   198,   201,   203,   205,   209,
     213,   216,   219,   223,   227,   233,   239,   241,   243,   246,
     248,   250,   252,   254,   256,   258,   260,   261,   265,   266,
     269,   270,   274,   277,   278,   286,   291,   296,   301,   307,
     309,   312,   313,   315,   316,   318,   323,   328,   333,   336,
     341
};
static const short yyrhs[] =
{
      -1,    70,    71,     0,    70,    73,     0,    70,    72,     0,
      70,    74,     0,    70,    75,     0,    70,    76,     0,    70,
      77,     0,    70,    78,     0,    70,    92,     0,    70,    93,
       0,     3,    64,     0,     3,    12,     0,    49,    64,     0,
      58,    85,     0,    58,    85,    68,     5,    67,     0,     4,
      85,    68,     5,    67,    84,     0,     4,    85,    50,    85,
      51,    96,     0,     4,    85,    52,    50,    85,     0,     4,
      85,    42,    65,    94,     0,     6,    81,    85,     0,     6,
      96,    81,    85,     0,     6,    81,    44,    64,     0,     7,
      64,    85,     0,    13,    85,    12,    68,    14,    84,     0,
      13,    85,    15,    86,     0,    13,    85,    60,    65,     0,
      13,    85,    26,    67,     0,    13,    85,    27,    28,    87,
       0,    13,    85,    27,    29,    87,     0,    13,    85,    30,
      67,     0,    13,    85,    30,    67,    31,    67,     0,    17,
      86,    79,     0,    17,    86,    80,     0,    32,    33,    81,
       0,    32,    33,    81,    46,    82,     0,    32,    81,     4,
      35,    82,    81,    88,    89,    90,    91,     0,    32,    81,
       4,    35,    82,    47,    81,    81,     0,    32,    81,    34,
      82,     0,    32,    81,    36,    82,     0,    19,     0,    18,
      19,     0,    20,    21,     0,    20,    22,     0,    20,    23,
       0,    66,     0,    65,     0,    81,    37,    67,     0,    81,
      24,    67,     0,    95,    64,     0,    95,    65,     0,    95,
      63,    65,     0,    95,    25,    83,     0,    95,    25,    64,
      24,    67,     0,    95,    25,    64,    24,    64,     0,     9,
       0,    11,     0,    95,    10,     0,    64,     0,    12,     0,
      81,     0,    65,     0,    16,     0,    69,     0,    67,     0,
       0,    38,    67,    39,     0,     0,    40,    87,     0,     0,
      41,    67,    67,     0,    41,    67,     0,     0,    21,    57,
      67,    39,    61,    67,    39,     0,    43,    64,    64,    67,
       0,    43,    64,    64,    69,     0,    43,    64,    64,    64,
       0,    43,    64,    64,    37,    64,     0,    59,     0,    59,
      85,     0,     0,    45,     0,     0,    48,     0,    54,    55,
      53,    65,     0,    54,    56,    53,    81,     0,    54,    56,
      53,    82,     0,    62,    97,     0,    57,    98,    61,    98,
       0,    67,    24,    67,    64,     0
};

#endif

#if YYDEBUG
/* YYRLINE[YYN] -- source line where rule number YYN was defined. */
static const short yyrline[] =
{
       0,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   136,   142,   147,   157,   162,   173,   181,   189,
     198,   213,   239,   262,   290,   298,   316,   322,   336,   342,
     353,   364,   375,   389,   395,   402,   408,   414,   445,   458,
     471,   486,   487,   489,   490,   491,   493,   499,   519,   540,
     552,   559,   569,   583,   591,   617,   633,   639,   645,   654,
     661,   667,   674,   682,   689,   693,   698,   699,   704,   705,
     710,   711,   715,   720,   721,   730,   741,   752,   764,   780,
     794,   811,   815,   821,   825,   831,   844,   852,   860,   870,
     877
};
#endif


#if (YYDEBUG) || defined YYERROR_VERBOSE

/* YYTNAME[TOKEN_NUM] -- String name of the token TOKEN_NUM. */
static const char *const yytname[] =
{
  "$", "error", "$undefined.", "CREATE", "ADD", "PORT", "BIND", "CLONE", 
  "DOT", "BLOCK", "OPEN", "RESET", "DEFAULT", "SET", "ACTION", 
  "PERSONALITY", "RANDOM", "ANNOTATE", "NO", "FINSCAN", "FRAGMENT", 
  "DROP", "OLD", "NEW", "COLON", "PROXY", "UPTIME", "DROPRATE", "IN", 
  "SYN", "UID", "GID", "ROUTE", "ENTRY", "LINK", "NET", "UNREACH", 
  "SLASH", "LATENCY", "MS", "LOSS", "BANDWIDTH", "SUBSYSTEM", "OPTION", 
  "TO", "SHARED", "NETWORK", "TUNNEL", "TARPIT", "DYNAMIC", "USE", "IF", 
  "OTHERWISE", "EQUAL", "SOURCE", "OS", "IP", "BETWEEN", "DELETE", "LIST", 
  "ETHERNET", "DASH", "TIME", "INTERNAL", "STRING", "CMDSTRING", 
  "IPSTRING", "NUMBER", "PROTO", "FLOAT", "config", "creation", "delete", 
  "addition", "subsystem", "binding", "set", "annotate", "route", 
  "finscan", "fragment", "ipaddr", "ipnet", "ipaddrplusport", "action", 
  "template", "personality", "rate", "latency", "packetloss", "bandwidth", 
  "randomearlydrop", "option", "ui", "shared", "flags", "condition", 
  "timecondition", "time", 0
};
#endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives. */
static const short yyr1[] =
{
       0,    70,    70,    70,    70,    70,    70,    70,    70,    70,
      70,    70,    71,    71,    71,    72,    72,    73,    73,    73,
      74,    75,    75,    75,    75,    76,    76,    76,    76,    76,
      76,    76,    76,    77,    77,    78,    78,    78,    78,    78,
      78,    79,    79,    80,    80,    80,    81,    81,    82,    83,
      84,    84,    84,    84,    84,    84,    84,    84,    84,    85,
      85,    85,    86,    86,    87,    87,    88,    88,    89,    89,
      90,    90,    90,    91,    91,    92,    92,    92,    92,    93,
      93,    94,    94,    95,    95,    96,    96,    96,    96,    97,
      98
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN. */
static const short yyr2[] =
{
       0,     0,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     5,     6,     6,     5,
       5,     3,     4,     4,     3,     6,     4,     4,     4,     5,
       5,     4,     6,     3,     3,     3,     5,    10,     8,     4,
       4,     1,     2,     2,     2,     2,     1,     1,     3,     3,
       2,     2,     3,     3,     5,     5,     1,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     0,     3,     0,     2,
       0,     3,     2,     0,     7,     4,     4,     4,     5,     1,
       2,     0,     1,     0,     1,     4,     4,     4,     2,     4,
       4
};

/* YYDEFACT[S] -- default rule to reduce with in state S when YYTABLE
   doesn't specify something else to do.  Zero means the default is an
   error. */
static const short yydefact[] =
{
       1,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    79,     2,     4,     3,     5,     6,     7,     8,
       9,    10,    11,    13,    12,    60,    59,    47,    46,    61,
       0,     0,     0,     0,     0,     0,     0,    63,    62,     0,
       0,     0,     0,    14,    15,    80,     0,     0,     0,     0,
       0,     0,     0,    88,     0,    21,     0,    24,     0,     0,
       0,     0,     0,     0,     0,    41,     0,    33,    34,    35,
       0,     0,     0,     0,     0,    81,     0,     0,     0,     0,
       0,     0,     0,    23,    22,     0,    26,    28,     0,     0,
      31,    27,    42,    43,    44,    45,     0,     0,     0,    39,
      40,     0,    77,    75,    76,     0,    82,    20,     0,    19,
      83,    85,    86,    87,     0,     0,    83,    65,    64,    29,
      30,     0,    36,     0,     0,    78,    16,    18,    56,    57,
      84,    17,     0,     0,    89,    25,    32,     0,    66,    48,
      58,     0,     0,    50,    51,    90,     0,     0,    68,     0,
       0,    53,    52,    38,     0,     0,    70,     0,     0,    67,
      69,     0,    73,    55,    54,    49,    72,     0,    37,    71,
       0,     0,     0,     0,     0,    74,     0,     0
};

static const short yydefgoto[] =
{
       1,    13,    14,    15,    16,    17,    18,    19,    20,    67,
      68,    29,    99,   151,   131,    30,    39,   119,   148,   156,
     162,   168,    21,    22,   107,   132,    34,    53,    82
};

static const short yypact[] =
{
  -32768,    14,     1,   -11,    44,   -55,   -11,   -14,   -17,   -49,
     -45,   -11,   -11,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
      39,   -31,   -23,    20,    -7,   -11,    11,-32768,-32768,    85,
      -7,    46,   -25,-32768,    -2,-32768,     9,   -11,    25,    73,
      30,    35,    23,-32768,    32,-32768,   -11,-32768,    26,   -14,
      34,    93,    41,    55,    80,-32768,    92,-32768,-32768,    77,
      89,    -7,    -7,    33,   120,    81,    76,   -11,    61,    64,
      -7,   106,    70,-32768,-32768,   118,-32768,-32768,   -24,   -24,
     103,-32768,-32768,-32768,-32768,-32768,    -7,    -7,    98,-32768,
  -32768,    72,-32768,-32768,-32768,    71,-32768,-32768,   -10,-32768,
      31,-32768,    98,-32768,    74,    23,    31,-32768,-32768,-32768,
  -32768,    78,-32768,   -37,    79,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,    -3,    75,-32768,-32768,-32768,    -7,   102,-32768,
  -32768,    52,    82,-32768,-32768,-32768,    -7,    83,   104,   119,
     124,-32768,-32768,-32768,   110,   -24,   111,   -59,    84,-32768,
  -32768,    86,   133,-32768,-32768,-32768,    88,    99,-32768,-32768,
      90,   121,    97,    94,   123,-32768,   159,-32768
};

static const short yypgoto[] =
{
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,    -4,    15,-32768,    47,     0,   105,   -86,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,    57,-32768,    51
};


#define	YYLAST		166


static const short yytable[] =
{
      33,    25,    37,   120,    41,   163,    36,   140,   164,    35,
     137,    44,    45,    23,   176,    42,    40,     2,     3,    43,
       4,     5,   141,    58,    50,    51,    59,     6,    27,    28,
      56,     7,    25,    55,    52,    57,    69,    60,    61,    73,
     128,    62,   129,   117,    31,   118,     8,    76,    27,    28,
      70,    38,    32,    26,    27,    28,    84,     9,    27,    28,
     142,   143,   144,    10,    54,    24,    74,    98,    98,   160,
     101,    63,    11,    12,    75,    77,   112,   109,    78,   130,
      71,    46,    72,    79,    26,    27,    28,   100,    80,    47,
      81,    48,    98,    98,    85,   113,    83,   102,    31,    92,
     103,    87,   104,    64,    65,    66,    32,    49,    90,    27,
      28,   122,   123,    93,    94,    95,   149,    27,    28,   138,
      91,    88,    89,    96,    97,   105,   106,   108,   110,   111,
     114,   115,   116,   146,   121,   124,   125,   150,   126,   145,
     147,   133,   153,   157,   155,   136,   139,   152,   158,   159,
     154,   165,   161,   166,   167,   169,   170,   171,   173,   177,
     172,   174,   175,   135,    86,   127,   134
};

static const short yycheck[] =
{
       4,    12,    16,    89,     8,    64,     6,    10,    67,    64,
      47,    11,    12,    12,     0,    64,    33,     3,     4,    64,
       6,     7,    25,    12,    55,    56,    15,    13,    65,    66,
      34,    17,    12,    33,    57,    35,    40,    26,    27,    64,
       9,    30,    11,    67,    54,    69,    32,    47,    65,    66,
       4,    65,    62,    64,    65,    66,    56,    43,    65,    66,
      63,    64,    65,    49,    44,    64,    68,    71,    72,   155,
      37,    60,    58,    59,    65,    50,    80,    77,     5,    48,
      34,    42,    36,    53,    64,    65,    66,    72,    53,    50,
      67,    52,    96,    97,    68,    80,    64,    64,    54,    19,
      67,    67,    69,    18,    19,    20,    62,    68,    67,    65,
      66,    96,    97,    21,    22,    23,    64,    65,    66,   123,
      65,    28,    29,    46,    35,     5,    45,    51,    67,    65,
      24,    61,    14,   137,    31,    37,    64,   141,    67,    64,
      38,    67,   146,    24,    40,    67,    67,    65,    24,    39,
      67,    67,    41,    67,    21,    67,    57,    67,    61,     0,
      39,    67,    39,   116,    59,   108,   115
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/local/share/bison/bison.simple"

/* Skeleton output parser for bison,

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software
   Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser when
   the %semantic_parser declaration is not specified in the grammar.
   It was written by Richard Stallman by simplifying the hairy parser
   used when %semantic_parser is specified.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

#if ! defined (yyoverflow) || defined (YYERROR_VERBOSE)

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC malloc
#  define YYSTACK_FREE free
# endif
#endif /* ! defined (yyoverflow) || defined (YYERROR_VERBOSE) */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (YYLTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
# if YYLSP_NEEDED
  YYLTYPE yyls;
# endif
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAX (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# if YYLSP_NEEDED
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE) + sizeof (YYLTYPE))	\
      + 2 * YYSTACK_GAP_MAX)
# else
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAX)
# endif

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAX;	\
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif


#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");			\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).

   When YYLLOC_DEFAULT is run, CURRENT is set the location of the
   first token.  By default, to implement support for ranges, extend
   its range to the last symbol.  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)       	\
   Current.last_line   = Rhs[N].last_line;	\
   Current.last_column = Rhs[N].last_column;
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#if YYPURE
# if YYLSP_NEEDED
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, &yylloc, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval, &yylloc)
#  endif
# else /* !YYLSP_NEEDED */
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval)
#  endif
# endif /* !YYLSP_NEEDED */
#else /* !YYPURE */
# define YYLEX			yylex ()
#endif /* !YYPURE */


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)
/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
#endif /* !YYDEBUG */

/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif

#ifdef YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif
#endif

#line 315 "/usr/local/share/bison/bison.simple"


/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
#  define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL
# else
#  define YYPARSE_PARAM_ARG YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
# endif
#else /* !YYPARSE_PARAM */
# define YYPARSE_PARAM_ARG
# define YYPARSE_PARAM_DECL
#endif /* !YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
# ifdef YYPARSE_PARAM
int yyparse (void *);
# else
int yyparse (void);
# endif
#endif

/* YY_DECL_VARIABLES -- depending whether we use a pure parser,
   variables are global, or local to YYPARSE.  */

#define YY_DECL_NON_LSP_VARIABLES			\
/* The lookahead symbol.  */				\
int yychar;						\
							\
/* The semantic value of the lookahead symbol. */	\
YYSTYPE yylval;						\
							\
/* Number of parse errors so far.  */			\
int yynerrs;

#if YYLSP_NEEDED
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES			\
						\
/* Location data for the lookahead symbol.  */	\
YYLTYPE yylloc;
#else
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES
#endif


/* If nonreentrant, generate the variables here. */

#if !YYPURE
YY_DECL_VARIABLES
#endif  /* !YYPURE */

int
yyparse (YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  /* If reentrant, generate the variables here. */
#if YYPURE
  YY_DECL_VARIABLES
#endif  /* !YYPURE */

  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yychar1 = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack. */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;

#if YYLSP_NEEDED
  /* The location stack.  */
  YYLTYPE yylsa[YYINITDEPTH];
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;
#endif

#if YYLSP_NEEDED
# define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
# define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  YYSIZE_T yystacksize = YYINITDEPTH;


  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
#if YYLSP_NEEDED
  YYLTYPE yyloc;
#endif

  /* When reducing, the number of symbols on the RHS of the reduced
     rule. */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;
#if YYLSP_NEEDED
  yylsp = yyls;
#endif
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  */
# if YYLSP_NEEDED
	YYLTYPE *yyls1 = yyls;
	/* This used to be a conditional around just the two extra args,
	   but that might be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);
	yyls = yyls1;
# else
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);
# endif
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);
# if YYLSP_NEEDED
	YYSTACK_RELOCATE (yyls);
# endif
# undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
#if YYLSP_NEEDED
      yylsp = yyls + yysize - 1;
#endif

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yychar1 = YYTRANSLATE (yychar);

#if YYDEBUG
     /* We have to keep this `#if YYDEBUG', since we use variables
	which are defined only if `YYDEBUG' is set.  */
      if (yydebug)
	{
	  YYFPRINTF (stderr, "Next token is %d (%s",
		     yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise
	     meaning of a token, for further debugging info.  */
# ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
# endif
	  YYFPRINTF (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %d (%s), ",
	      yychar, yytname[yychar1]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to the semantic value of
     the lookahead token.  This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

#if YYLSP_NEEDED
  /* Similarly for the default location.  Let the user run additional
     commands if for instance locations are ranges.  */
  yyloc = yylsp[1-yylen];
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
#endif

#if YYDEBUG
  /* We have to keep this `#if YYDEBUG', since we use variables which
     are defined only if `YYDEBUG' is set.  */
  if (yydebug)
    {
      int yyi;

      YYFPRINTF (stderr, "Reducing via rule %d (line %d), ",
		 yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (yyi = yyprhs[yyn]; yyrhs[yyi] > 0; yyi++)
	YYFPRINTF (stderr, "%s ", yytname[yyrhs[yyi]]);
      YYFPRINTF (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif

  switch (yyn) {

case 12:
#line 137 "parse.y"
{
		if (template_create(yyvsp[0].string) == NULL)
			yyerror("Template \"%s\" exists already", yyvsp[0].string);
		free(yyvsp[0].string);
	}
    break;
case 13:
#line 143 "parse.y"
{
		if (template_create("default") == NULL)
			yyerror("Template \"default\" exists already");
	}
    break;
case 14:
#line 148 "parse.y"
{		
		struct template *tmpl;
		if ((tmpl = template_create(yyvsp[0].string)) == NULL)
			yyerror("Template \"%s\" exists already", yyvsp[0].string);
		tmpl->flags |= TEMPLATE_DYNAMIC;
		free(yyvsp[0].string);
	}
    break;
case 15:
#line 158 "parse.y"
{
		if (yyvsp[0].tmpl != NULL)
			template_free(yyvsp[0].tmpl);
	}
    break;
case 16:
#line 163 "parse.y"
{
		struct port *port;
		if ((port = port_find(yyvsp[-3].tmpl, yyvsp[-2].number, yyvsp[0].number)) == NULL) {
			yyerror("Cannot find port %d in \"%s\"",
			    yyvsp[0].number, yyvsp[-3].tmpl->name);
		} else {
			port_free(yyvsp[-3].tmpl, port);
		}
	}
    break;
case 17:
#line 174 "parse.y"
{
		if (yyvsp[-4].tmpl != NULL && template_add(yyvsp[-4].tmpl, yyvsp[-3].number, yyvsp[-1].number, &yyvsp[0].action) == -1)
			yyerror("Can not add port %d to template \"%s\"",
			    yyvsp[-1].number, yyvsp[-4].tmpl != NULL ? yyvsp[-4].tmpl->name : "<unknown>");
		if (yyvsp[0].action.action)
			free(yyvsp[0].action.action);
	}
    break;
case 18:
#line 182 "parse.y"
{	
		if (yyvsp[-4].tmpl == NULL || yyvsp[-2].tmpl == NULL)
			break;
		if (!(yyvsp[-4].tmpl->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", yyvsp[-4].tmpl->name);
		template_insert_dynamic(yyvsp[-4].tmpl, yyvsp[-2].tmpl, &yyvsp[0].condition);
	}
    break;
case 19:
#line 190 "parse.y"
{	
		if (yyvsp[-3].tmpl == NULL || yyvsp[0].tmpl == NULL)
			break;
		if (!(yyvsp[-3].tmpl->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", yyvsp[-3].tmpl->name);
		template_insert_dynamic(yyvsp[-3].tmpl, yyvsp[0].tmpl, NULL);
	}
    break;
case 20:
#line 199 "parse.y"
{
		struct addr tmp;
		int isaddr;

		isaddr = addr_aton(yyvsp[-3].tmpl->name, &tmp) == -1 ? 0 : 1;

		yyvsp[-1].string[strlen(yyvsp[-1].string) - 1] = '\0';
		if (yyvsp[-3].tmpl != NULL &&
		    template_subsystem(yyvsp[-3].tmpl, yyvsp[-1].string+1, isaddr, yyvsp[0].number) == -1)
			yyerror("Can not add subsystem \"%s\" to template \"%s\"",
			    yyvsp[-1].string+1, yyvsp[-3].tmpl != NULL ? yyvsp[-3].tmpl->name : "<unknown>");
		free(yyvsp[-1].string);
	}
    break;
case 21:
#line 214 "parse.y"
{
		/* Bind to an IP address and start subsystems */
		if (yyvsp[0].tmpl == NULL) {
			yyerror("Unknown template");
			break;
		}

		if (yyvsp[0].tmpl->ethernet_addr != NULL) {
			struct interface *inter;
			inter = interface_find_responsible(&yyvsp[-1].addr);
			if (inter == NULL ||
			    inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
				yyerror("Template \"%s\" is configured with "
				    "ethernet address but there is no "
				    "interface that can reach %s",
				    yyvsp[0].tmpl->name, addr_ntoa(&yyvsp[-1].addr));
				break;
			}
		}

		if (template_clone(addr_ntoa(&yyvsp[-1].addr), yyvsp[0].tmpl, 1) == NULL) {
			yyerror("Binding to %s failed", addr_ntoa(&yyvsp[-1].addr));
			break;
		}
	}
    break;
case 22:
#line 240 "parse.y"
{
		struct template *tmpl;

		/* Special magic */
		if ((tmpl = template_find(addr_ntoa(&yyvsp[-1].addr))) != NULL) {
			if (!(tmpl->flags & TEMPLATE_DYNAMIC)) {
				yyerror("Template \"%s\" already specified as "
				    "non-dynamic template", addr_ntoa(&yyvsp[-1].addr));
				break;
			}
		} else if ((tmpl = template_create(addr_ntoa(&yyvsp[-1].addr))) == NULL) {
			yyerror("Could not create template \"%s\"",
			    addr_ntoa(&yyvsp[-1].addr));
			break;
		}

		/* 
		 * Add this point we do have the right template.
		 * We just need to add the proper condition.
		 */
		template_insert_dynamic(tmpl, yyvsp[0].tmpl, &yyvsp[-2].condition);
	}
    break;
case 23:
#line 263 "parse.y"
{
		struct interface *inter;
		struct template *tmpl;

		/* Bind an IP address to an external interface */
		if ((inter = interface_find(yyvsp[0].string)) == NULL) {
			yyerror("Interface \"%s\" does not exist.", yyvsp[0].string);
			free(yyvsp[0].string);
			break;
		}
		if (inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
			yyerror("Interface \"%s\" does not support arp.", yyvsp[0].string);
			free(yyvsp[0].string);
			break;
		}

		if ((tmpl = template_create(addr_ntoa(&yyvsp[-2].addr))) == NULL) {
			yyerror("Template \"%s\" exists already",
			    addr_ntoa(&yyvsp[-2].addr));
			break;
		}

		/* Make this template external. */
		tmpl->flags |= TEMPLATE_EXTERNAL;
		tmpl->inter = inter;
		free(yyvsp[0].string);
	}
    break;
case 24:
#line 291 "parse.y"
{
		/* Just clone.  This is not the final destination yet */
		if (yyvsp[0].tmpl == NULL || template_clone(yyvsp[-1].string, yyvsp[0].tmpl, 0) == NULL)
			yyerror("Cloning to %s failed", yyvsp[-1].string);
		free(yyvsp[-1].string);
	}
    break;
case 25:
#line 299 "parse.y"
{
		struct action *action;

		if (yyvsp[-4].tmpl == NULL) {
			yyerror("No template");
			break;
		}
		
		if ((action = honeyd_protocol(yyvsp[-4].tmpl, yyvsp[-2].number)) == NULL) {
			yyerror("Bad protocol");
			break;
		}

		port_action_clone(action, &yyvsp[0].action);
		if (yyvsp[0].action.action != NULL)
			free(yyvsp[0].action.action);
	}
    break;
case 26:
#line 317 "parse.y"
{
		if (yyvsp[-2].tmpl == NULL || yyvsp[0].pers == NULL)
			break;
		yyvsp[-2].tmpl->person = personality_clone(yyvsp[0].pers);
	}
    break;
case 27:
#line 323 "parse.y"
{
		extern int need_arp;
		if (yyvsp[-2].tmpl == NULL || yyvsp[0].string == NULL)
			break;
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		yyvsp[-2].tmpl->ethernet_addr = ethernetcode_make_address(yyvsp[0].string + 1);
		if (yyvsp[-2].tmpl->ethernet_addr == NULL) {
			yyerror("Unknown ethernet vendor \"%s\"", yyvsp[0].string + 1);
		}
		free (yyvsp[0].string);

		need_arp = 1;
	}
    break;
case 28:
#line 337 "parse.y"
{
		if (yyvsp[-2].tmpl == NULL || yyvsp[0].number == 0)
			break;
		yyvsp[-2].tmpl->timestamp = yyvsp[0].number * 2;
	}
    break;
case 29:
#line 343 "parse.y"
{
		if (yyvsp[-3].tmpl == NULL)
			break;
		if (yyvsp[0].floatp > 100) {
			yyerror("Droprate too high: %f", yyvsp[0].floatp);
			break;
		}

		yyvsp[-3].tmpl->drop_inrate = yyvsp[0].floatp * 100;
	}
    break;
case 30:
#line 354 "parse.y"
{
		if (yyvsp[-3].tmpl == NULL)
			break;
		if (yyvsp[0].floatp > 100) {
			yyerror("Droprate too high: %f", yyvsp[0].floatp);
			break;
		}

		yyvsp[-3].tmpl->drop_synrate = yyvsp[0].floatp * 100;
	}
    break;
case 31:
#line 365 "parse.y"
{
		if (yyvsp[-2].tmpl == NULL)
			break;
		if (!yyvsp[0].number) {
			yyerror("Bad uid %d", yyvsp[0].number);
			break;
		}
		yyvsp[-2].tmpl->uid = yyvsp[0].number;
		honeyd_use_uid(yyvsp[0].number);
	}
    break;
case 32:
#line 376 "parse.y"
{
		if (yyvsp[-4].tmpl == NULL)
			break;
		if (!yyvsp[-2].number || !yyvsp[0].number) {
			yyerror("Bad uid %d, gid %d", yyvsp[-2].number, yyvsp[0].number);
			break;
		}
		yyvsp[-4].tmpl->uid = yyvsp[-2].number;
		yyvsp[-4].tmpl->gid = yyvsp[0].number;
		honeyd_use_uid(yyvsp[-2].number);
		honeyd_use_gid(yyvsp[0].number);
	}
    break;
case 33:
#line 390 "parse.y"
{
		if (yyvsp[-1].pers == NULL)
			break;
		yyvsp[-1].pers->disallow_finscan = !yyvsp[0].number;
	}
    break;
case 34:
#line 396 "parse.y"
{
		if (yyvsp[-1].pers == NULL)
			break;
		yyvsp[-1].pers->fragp = yyvsp[0].fragp;
	}
    break;
case 35:
#line 403 "parse.y"
{
		if (router_start(&yyvsp[0].addr, NULL) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&yyvsp[0].addr));
	}
    break;
case 36:
#line 409 "parse.y"
{
		if (router_start(&yyvsp[-2].addr, &yyvsp[0].addr) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&yyvsp[-2].addr));
	}
    break;
case 37:
#line 415 "parse.y"
{
		struct router *r, *newr;
		struct addr defroute;

		if ((r = router_find(&yyvsp[-8].addr)) == NULL &&
		    (r = router_new(&yyvsp[-8].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-8].addr));
			break;
		}
		if ((newr = router_find(&yyvsp[-4].addr)) == NULL)
			newr = router_new(&yyvsp[-4].addr);
		if (router_add_net(r, &yyvsp[-5].addr, newr, yyvsp[-3].number, yyvsp[-2].number, yyvsp[-1].number, &yyvsp[0].drop) == -1)
			yyerror("Could not add route to %s", addr_ntoa(&yyvsp[-5].addr));

		if (yyvsp[-1].number == 0 && yyvsp[0].drop.high != 0)
			yywarn("Ignoring drop between statement without "
			       "specified bandwidth.");

		addr_pton("0.0.0.0/0", &defroute);
		defroute.addr_bits = 0; /* work around libdnet bug */

		/* Only insert a reverse route, if the current route is
		 * not the default route.
		 */
		if (addr_cmp(&defroute, &yyvsp[-5].addr) != 0 &&
		    router_add_net(newr, &defroute, r, yyvsp[-3].number, yyvsp[-2].number, yyvsp[-1].number, &yyvsp[0].drop) == -1)
			yyerror("Could not add default route to %s",
			    addr_ntoa(&yyvsp[-5].addr));
	}
    break;
case 38:
#line 446 "parse.y"
{
		struct router *r;

		if ((r = router_find(&yyvsp[-6].addr)) == NULL &&
		    (r = router_new(&yyvsp[-6].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-6].addr));
			break;
		}
		if (router_add_tunnel(r, &yyvsp[-3].addr, &yyvsp[-1].addr, &yyvsp[0].addr) == -1)
			yyerror("Could not add tunnel to %s", addr_ntoa(&yyvsp[0].addr));
	}
    break;
case 39:
#line 459 "parse.y"
{
		struct router *r;

		if ((r = router_find(&yyvsp[-2].addr)) == NULL &&
		    (r = router_new(&yyvsp[-2].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-2].addr));
			break;
		}
		if (router_add_link(r, &yyvsp[0].addr) == -1)
			yyerror("Could not add link %s", addr_ntoa(&yyvsp[0].addr));
	}
    break;
case 40:
#line 472 "parse.y"
{
		struct router *r;

		if ((r = router_find(&yyvsp[-2].addr)) == NULL &&
		    (r = router_new(&yyvsp[-2].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-2].addr));
			break;
		}
		if (router_add_unreach(r, &yyvsp[0].addr) == -1)
			yyerror("Could not add unreachable net %s",
			    addr_ntoa(&yyvsp[0].addr));
	}
    break;
case 41:
#line 486 "parse.y"
{ yyval.number = 1; }
    break;
case 42:
#line 487 "parse.y"
{ yyval.number = 0; }
    break;
case 43:
#line 489 "parse.y"
{ yyval.fragp = FRAG_DROP; }
    break;
case 44:
#line 490 "parse.y"
{ yyval.fragp = FRAG_OLD; }
    break;
case 45:
#line 491 "parse.y"
{ yyval.fragp = FRAG_NEW; }
    break;
case 46:
#line 494 "parse.y"
{
		if (addr_pton(yyvsp[0].string, &yyval.addr) < 0)
			yyerror("Illegal IP address %s", yyvsp[0].string);
		free(yyvsp[0].string);
	}
    break;
case 47:
#line 500 "parse.y"
{
		struct addrinfo ai, *aitop;

		memset(&ai, 0, sizeof (ai));
		ai.ai_family = AF_INET;
		ai.ai_socktype = 0;
		ai.ai_flags = 0;

		/* Remove quotation marks */
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if (getaddrinfo(yyvsp[0].string+1, NULL, &ai, &aitop) != 0) {
			yyerror("getaddrinfo failed: %s", yyvsp[0].string+1);
			break;
		}
		addr_ston(aitop->ai_addr, &yyval.addr);
		freeaddrinfo(aitop);
		free(yyvsp[0].string);
	}
    break;
case 48:
#line 520 "parse.y"
{
		char src[25];
		struct addr b;
		snprintf(src, sizeof(src), "%s/%d",
		    addr_ntoa(&yyvsp[-2].addr), yyvsp[0].number);
		if (addr_pton(src, &yyval.addr) < 0)
			yyerror("Illegal IP network %s", src);
		/* Fix libdnet error */
		if (yyvsp[0].number == 0)
			yyval.addr.addr_bits = 0;

		/* Test if this is a legal network */
		addr_net(&yyval.addr, &b);
		b.addr_bits = yyval.addr.addr_bits;
		if (memcmp(&yyval.addr.addr_ip, &b.addr_ip, IP_ADDR_LEN)) {
			yyval.addr = b;
			yywarn("Bad network mask in %s", src);
		}
	}
    break;
case 49:
#line 541 "parse.y"
{
		if (curtype == -1) {
			yyerror("Bad port type");
			break;
		}
		yyval.ai = cmd_proxy_getinfo(addr_ntoa(&yyvsp[-2].addr), curtype, yyvsp[0].number);
		curtype = -1;
		if (yyval.ai == NULL)
			yyerror("Illegal IP address port pair");
	}
    break;
case 50:
#line 553 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.action = yyvsp[0].string;
		yyval.action.flags = yyvsp[-1].number;
		yyval.action.status = PORT_OPEN;
	}
    break;
case 51:
#line 560 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if ((yyval.action.action = strdup(yyvsp[0].string + 1)) == NULL)
			yyerror("Out of memory");
		yyval.action.status = PORT_OPEN;
		yyval.action.flags = yyvsp[-1].number;
		free(yyvsp[0].string);
	}
    break;
case 52:
#line 570 "parse.y"
{
#ifdef HAVE_PYTHON
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if ((yyval.action.action_extend = pyextend_load_module(yyvsp[0].string+1)) == NULL)
			yyerror("Bad python module: \"%s\"", yyvsp[0].string+1);
		yyval.action.status = PORT_PYTHON;
		yyval.action.flags = yyvsp[-2].number;
		free(yyvsp[0].string);
#else
		yyerror("Python support is not available.");
#endif
	}
    break;
case 53:
#line 584 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_PROXY;
		yyval.action.action = NULL;
		yyval.action.aitop = yyvsp[0].ai;
		yyval.action.flags = yyvsp[-2].number;
	}
    break;
case 54:
#line 592 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_PROXY;
		yyval.action.action = NULL;
		yyval.action.aitop = NULL;
		yyval.action.flags = yyvsp[-4].number;
		if (yyvsp[-2].string[0] != '$') {
			if (curtype == -1) {
				yyerror("Bad port type");
				break;
			}
			yyval.action.aitop = cmd_proxy_getinfo(yyvsp[-2].string, curtype, yyvsp[0].number);
			curtype = -1;
			if (yyval.action.aitop == NULL)
				yyerror("Illegal host name in proxy");
		} else {
			char proxy[1024];

			snprintf(proxy, sizeof(proxy), "%s:%d", yyvsp[-2].string, yyvsp[0].number);
			yyval.action.action = strdup(proxy);
			if (yyval.action.action == NULL)
				yyerror("Out of memory");
		}
		free(yyvsp[-2].string);
	}
    break;
case 55:
#line 618 "parse.y"
{
		char proxy[1024];
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_PROXY;
		yyval.action.action = NULL;
		yyval.action.aitop = NULL;
		yyval.action.flags = yyvsp[-4].number;

		snprintf(proxy, sizeof(proxy), "%s:%s", yyvsp[-2].string, yyvsp[0].string);
		yyval.action.action = strdup(proxy);
		if (yyval.action.action == NULL)
				yyerror("Out of memory");
		free(yyvsp[-2].string);
		free(yyvsp[0].string);
	}
    break;
case 56:
#line 634 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_BLOCK;
		yyval.action.action = NULL;
	}
    break;
case 57:
#line 640 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_RESET;
		yyval.action.action = NULL;
	}
    break;
case 58:
#line 646 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_OPEN;
		yyval.action.action = NULL;
		yyval.action.flags = yyvsp[-1].number;
	}
    break;
case 59:
#line 655 "parse.y"
{
		yyval.tmpl = template_find(yyvsp[0].string);
		if (yyval.tmpl == NULL)
			yyerror("Unknown template \"%s\"", yyvsp[0].string);
		free(yyvsp[0].string);
	}
    break;
case 60:
#line 662 "parse.y"
{
		yyval.tmpl = template_find("default");
		if (yyval.tmpl == NULL)
			yyerror("Unknown template \"%s\"", "default");
	}
    break;
case 61:
#line 668 "parse.y"
{
		yyval.tmpl = template_find(addr_ntoa(&yyvsp[0].addr));
		if (yyval.tmpl == NULL)
			yyerror("Unknown template \"%s\"", addr_ntoa(&yyvsp[0].addr));
	}
    break;
case 62:
#line 675 "parse.y"
{
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		yyval.pers = personality_find(yyvsp[0].string+1);
		if (yyval.pers == NULL)
			yyerror("Unknown personality \"%s\"", yyvsp[0].string+1);
		free(yyvsp[0].string);
	}
    break;
case 63:
#line 683 "parse.y"
{
		yyval.pers = personality_random();
		if (yyval.pers == NULL)
			yyerror("Random personality failed");
	}
    break;
case 64:
#line 690 "parse.y"
{
		yyval.floatp = yyvsp[0].floatp;
	}
    break;
case 65:
#line 694 "parse.y"
{
		yyval.floatp = yyvsp[0].number;
	}
    break;
case 66:
#line 698 "parse.y"
{ yyval.number = 0; }
    break;
case 67:
#line 700 "parse.y"
{
		yyval.number = yyvsp[-1].number;
	}
    break;
case 68:
#line 704 "parse.y"
{ yyval.number = 0; }
    break;
case 69:
#line 706 "parse.y"
{
		yyval.number = yyvsp[0].floatp * 100;
	}
    break;
case 70:
#line 710 "parse.y"
{ yyval.number = 0; }
    break;
case 71:
#line 712 "parse.y"
{
		yyval.number = yyvsp[-1].number * yyvsp[0].number;
	}
    break;
case 72:
#line 716 "parse.y"
{
		yyval.number = yyvsp[0].number;
	}
    break;
case 73:
#line 720 "parse.y"
{ memset(&yyval.drop, 0, sizeof(yyval.drop)); }
    break;
case 74:
#line 722 "parse.y"
{
		if (yyvsp[-1].number <= yyvsp[-4].number)
			yyerror("Incorrect thresholds. First number needs to "
				"be smaller than second number.");
		yyval.drop.low = yyvsp[-4].number;
		yyval.drop.high = yyvsp[-1].number;
	}
    break;
case 75:
#line 731 "parse.y"
{
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_int = yyvsp[0].number;
		cfg.cfg_type = HD_CONFIG_INT;
		plugins_config_item_add(yyvsp[-2].string, yyvsp[-1].string, &cfg);
		
		free(yyvsp[-2].string); free(yyvsp[-1].string);
	}
    break;
case 76:
#line 742 "parse.y"
{
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_flt = yyvsp[0].floatp;
		cfg.cfg_type = HD_CONFIG_FLT;
		plugins_config_item_add(yyvsp[-2].string, yyvsp[-1].string, &cfg);

		free(yyvsp[-2].string); free(yyvsp[-1].string);
        }
    break;
case 77:
#line 753 "parse.y"
{
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = yyvsp[0].string;
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add(yyvsp[-2].string, yyvsp[-1].string, &cfg);

		free(yyvsp[-2].string); free(yyvsp[-1].string); free(yyvsp[0].string);
        }
    break;
case 78:
#line 765 "parse.y"
{
		struct honeyd_plugin_cfg cfg;
		char path[MAXPATHLEN];

		snprintf(path, sizeof(path), "/%s", yyvsp[0].string);

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = path;
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add(yyvsp[-3].string, yyvsp[-2].string, &cfg);

		free(yyvsp[-3].string); free(yyvsp[-2].string); free(yyvsp[0].string);
        }
    break;
case 79:
#line 781 "parse.y"
{
	extern struct templtree templates;
	struct template *tmpl;
	int count = 0;

	SPLAY_FOREACH(tmpl, templtree, &templates) {
		count++;
		yyprintf("%4d. %s (%s)\n",
		    count,
		    tmpl->name,
		    tmpl->person != NULL ? tmpl->person->name : "undefined");
	}
}
    break;
case 80:
#line 795 "parse.y"
{
	if (yyvsp[0].tmpl != NULL) {
		yyprintf("template %s:\n", yyvsp[0].tmpl->name);
		yyprintf("\tpersonality: %s\n",
		    yyvsp[0].tmpl->person != NULL ? yyvsp[0].tmpl->person->name : "undefined");
		if (yyvsp[0].tmpl->ethernet_addr != NULL)
			yyprintf("\tethernet address: %s\n",
			    addr_ntoa(yyvsp[0].tmpl->ethernet_addr));
		yyprintf("\tIP id: %d\n", yyvsp[0].tmpl->id);
		yyprintf("\tTCP seq: %ld\n", yyvsp[0].tmpl->seq);
		yyprintf("\tTCP drop: in: %d syn: %d\n",
		    yyvsp[0].tmpl->drop_inrate, yyvsp[0].tmpl->drop_synrate);
		yyprintf("\trefcnt: %d\n", yyvsp[0].tmpl->refcnt);
	}
}
    break;
case 81:
#line 812 "parse.y"
{
	yyval.number = 0;
}
    break;
case 82:
#line 816 "parse.y"
{
	yyval.number = 1;
}
    break;
case 83:
#line 822 "parse.y"
{
	yyval.number = 0;
}
    break;
case 84:
#line 826 "parse.y"
{
	yyval.number = PORT_TARPIT;
}
    break;
case 85:
#line 832 "parse.y"
{
		pf_osfp_t fp;
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if ((fp = pfctl_get_fingerprint(yyvsp[0].string+1)) == PF_OSFP_NOMATCH)
			yyerror("Unknown fingerprint \"%s\"", yyvsp[0].string+1);
		if ((yyval.condition.match_arg = malloc(sizeof(fp))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &fp, sizeof(fp));
		yyval.condition.match = condition_match_osfp;
		yyval.condition.match_arglen = sizeof(fp);
		free (yyvsp[0].string);
	}
    break;
case 86:
#line 845 "parse.y"
{
		if ((yyval.condition.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &yyvsp[0].addr, sizeof(struct addr));
		yyval.condition.match = condition_match_addr;
		yyval.condition.match_arglen = sizeof(struct addr);
	}
    break;
case 87:
#line 853 "parse.y"
{
		if ((yyval.condition.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &yyvsp[0].addr, sizeof(struct addr));
		yyval.condition.match = condition_match_addr;
		yyval.condition.match_arglen = sizeof(struct addr);
	}
    break;
case 88:
#line 861 "parse.y"
{
		if ((yyval.condition.match_arg = malloc(sizeof(struct condition_time))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &yyvsp[0].timecondition, sizeof(struct condition_time));
		yyval.condition.match = condition_match_time;
		yyval.condition.match_arglen = sizeof(struct condition_time);
	}
    break;
case 89:
#line 871 "parse.y"
{
		yyval.timecondition.tm_start = yyvsp[-2].time;
		yyval.timecondition.tm_end = yyvsp[0].time;
	}
    break;
case 90:
#line 878 "parse.y"
{
		int ispm = -1;
		int hour, minute;

		if (strcmp(yyvsp[0].string, "am") == 0) {
			ispm = 0;
		} else if (strcmp(yyvsp[0].string, "pm") == 0) {
			ispm = 1;
		} else {
			yyerror("Bad time specifier, use 'am' or 'pm': %s", yyvsp[0].string);
			break;
		}
		free (yyvsp[0].string);

		hour = yyvsp[-3].number + (ispm ? 12 : 0);
		minute = yyvsp[-1].number;

		memset(&yyval.time, 0, sizeof(yyval.time));
		yyval.time.tm_hour = hour;
		yyval.time.tm_min = minute;
	}
    break;
}

#line 705 "/usr/local/share/bison/bison.simple"


  yyvsp -= yylen;
  yyssp -= yylen;
#if YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;
#if YYLSP_NEEDED
  *++yylsp = yyloc;
#endif

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("parse error, unexpected ") + 1;
	  yysize += yystrlen (yytname[YYTRANSLATE (yychar)]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "parse error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[YYTRANSLATE (yychar)]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exhausted");
	}
      else
#endif /* defined (YYERROR_VERBOSE) */
	yyerror ("parse error");
    }
  goto yyerrlab1;


/*--------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action |
`--------------------------------------------------*/
yyerrlab1:
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;
      YYDPRINTF ((stderr, "Discarding token %d (%s).\n",
		  yychar, yytname[yychar1]));
      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;


/*-------------------------------------------------------------------.
| yyerrdefault -- current state does not do anything special for the |
| error token.                                                       |
`-------------------------------------------------------------------*/
yyerrdefault:
#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */

  /* If its default is to accept any token, ok.  Otherwise pop it.  */
  yyn = yydefact[yystate];
  if (yyn)
    goto yydefault;
#endif


/*---------------------------------------------------------------.
| yyerrpop -- pop the current state because it cannot handle the |
| error token                                                    |
`---------------------------------------------------------------*/
yyerrpop:
  if (yyssp == yyss)
    YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#if YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "Error: state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

/*--------------.
| yyerrhandle.  |
`--------------*/
yyerrhandle:
  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

/*---------------------------------------------.
| yyoverflowab -- parser overflow comes here.  |
`---------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}
#line 900 "parse.y"


int
yyerror(char *fmt, ...)
{
	va_list ap;
	errors = 1;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		buffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yywarn(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		buffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yyprintf(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		vfprintf(stdout, fmt, ap);
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		buffer_add_printf(buffer, "%s", data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
parse_configuration(FILE *input, char *name)
{
	extern FILE *yyin;

	buffer = NULL;
	errors = 0;
	lineno = 1;
	filename = name;
	yyin = input;
	yyparse();
	return (errors ? -1 : 0);
}

/*
 * Parse from memory.  Error output is buffered
 */

int
parse_line(struct buffer *output, char *line)
{
	void *yybuf;

	buffer = output;
	errors = 0;
	lineno = 1;
	filename = "<stdin>";
	yybuf = yy_scan_string(line);
	yyparse();
	yy_delete_buffer(yybuf);
	return (errors ? -1 : 0);
}
