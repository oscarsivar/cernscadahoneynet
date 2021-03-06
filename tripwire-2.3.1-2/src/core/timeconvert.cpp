//
// The developer of the original code and/or files is Tripwire, Inc.
// Portions created by Tripwire, Inc. are copyright (C) 2000 Tripwire,
// Inc. Tripwire is a registered trademark of Tripwire, Inc.  All rights
// reserved.
// 
// This program is free software.  The contents of this file are subject
// to the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.  You may redistribute it and/or modify it
// only in compliance with the GNU General Public License.
// 
// This program is distributed in the hope that it will be useful.
// However, this program is distributed AS-IS WITHOUT ANY
// WARRANTY; INCLUDING THE IMPLIED WARRANTY OF MERCHANTABILITY OR FITNESS
// FOR A PARTICULAR PURPOSE.  Please see the GNU General Public License
// for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
// USA.
// 
// Nothing in the GNU General Public License or any other license to use
// the code or files shall permit you to use Tripwire's trademarks,
// service marks, or other intellectual property without Tripwire's
// prior written consent.
// 
// If you have any questions, please contact Tripwire, Inc. at either
// info@tripwire.org or www.tripwire.org.
//
///////////////////////////////////////////////////////////////////////////////
// timeconvert.cpp
//

//=========================================================================
// INCLUDES
//=========================================================================

#include "stdcore.h"
#include "timeconvert.h"
#include "debug.h"
#include "stringutil.h"

//=========================================================================
// STANDARD LIBRARY INCLUDES
//=========================================================================

#include <time.h>

//=========================================================================
// METHOD CODE
//=========================================================================

static int64 TIME_MAX = 2147483647; // largest signed 32 bit number

struct tm* cTimeUtil::TimeToDateGMT( const int64& seconds )
{
    ASSERT( seconds < TIME_MAX );// this assumes time_t size is 32 bit.  Yikes!
    time_t t = static_cast<time_t>(seconds);
    return gmtime( &t );
}

struct tm* cTimeUtil::TimeToDateLocal( const int64& seconds )
{
    ASSERT( seconds < TIME_MAX );// this assumes time_t size is 32 bit.  Yikes!
    time_t t = static_cast<time_t>(seconds);
    tzset();
    return localtime( &t );
}

int64 cTimeUtil::DateToTime( struct tm* ptm )
{
    tzset();
    return mktime( ptm );
}

int64 cTimeUtil::GetTime()
{   
    return time( NULL );
}


