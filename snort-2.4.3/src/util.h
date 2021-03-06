/* $Id: util.h,v 1.15.6.2.2.1 2005/09/01 18:07:06 ssturges Exp $ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#ifndef __UTIL_H__
#define __UTIL_H__

#define TIMEBUF_SIZE 26

#ifndef WIN32
#include <sys/time.h>
#include <sys/types.h>
#endif /* !WIN32 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRLCAT
#include "strlcatu.h"
#endif

#ifndef HAVE_STRLCPY
#include "strlcpyu.h"
#endif

#include "sfsnprintfappend.h"

extern u_long netmasks[33];

/* Self preservation memory control struct */
typedef struct _SPMemControl
{
    unsigned long memcap;
    unsigned long mem_usage;
    void *control;
    int (*sp_func)(struct _SPMemControl *);

    unsigned long fault_count;

} SPMemControl;


int DisplayBanner();
void GetTime(char *);
int gmt2local(time_t);
void ts_print(register const struct timeval *, char *);
char *copy_argv(char **);
int strip(char *);
float CalcPct(float, float);
void ReadPacketsFromFile();
void GenHomenet(char *);
void InitNetmasks();
void InitBinFrag();
void GoDaemon();
void CheckLogDir();
char *read_infile(char *);
void InitProtoNames();
void CleanupProtoNames();
void PrintError(char *);
void ErrorMessage(const char *, ...);
void LogMessage(const char *, ...);
void FatalError(const char *, ...);
void FatalPrintError(char *);
void CreatePidFile(char *);
void SetUidGid(void);
void SetChroot(char *, char **);
void DropStats(int);
void GenObfuscationMask(char *);
void *SPAlloc(unsigned long, struct _SPMemControl *);
void *SnortAlloc(unsigned long);
char *CurrentWorkingDir(void);
char *GetAbsolutePath(char *dir);
char *StripPrefixDir(char *prefix, char *dir);
#ifdef TIMESTATS
void DropHourlyStats(int trap);
#endif

#endif /*__UTIL_H__*/
