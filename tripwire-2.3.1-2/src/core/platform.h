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
// platform.h
//

#ifndef __PLATFORM_H
#define __PLATFORM_H

//=============================================================================
// Enumerations
// 
// For each of these "enumerations" we create unique integers identifying each
// variation.  We group similar items together, such as OS_REDHAT and OS_SLACKWARE

#define OS_UNKNOWN		0
#define OS_WIN32		0x0101
#define OS_REDHAT5		0x0201
#define OS_REDHAT6		0x0202
#define OS_SLACKWARE	0x0203
#define OS_SOLARIS		0x0301
#define OS_AIX			0x0401
#define OS_HPUX			0x0501
#define OS_IRIX			0x0601
#define OS_OSF1			0x0701
#define OS_BSD			0x0801

#define ARCH_UNKNOWN		0
#define ARCH_IX86		0x0101
#define ARCH_SPARC		0x0201
#define ARCH_ALPHA		0x0301
#define ARCH_RS6000		0x0401
#define ARCH_PARISC		0x0501
#define ARCH_MIPS		0x0601

#define COMP_UNKNOWN		0
#define COMP_MSVC		    0x0101
#define COMP_KAI_GCC		0x0201
#define COMP_KAI_SUNPRO		0x0202
#define COMP_KAI_GLIBC		0x0203
#define COMP_KAI_VISUALAGE	0x0204
#define COMP_KAI_HPANSIC	0x0205
#define COMP_KAI_IRIX		0x0206
#define COMP_KAI_OSF1ALPHA	0x0207
#define COMP_SUNPRO		    0x0301
#define COMP_GCC		    0x0401

//=============================================================================
// Platform detection
//
// Using boolean logic on predefined compilers variables, detect and set
// PLATFORM preprosessor defines to the unique ID specified above.
//
// The following definitions are set in this section:
//
//      OS                  The OS
//      COMP                The compiler
//      ARCH                The cpu type
//
// PLEASE NOTE:  Do not set any preprocessor variable other than the above three in this 
// section.  Use the following sections for anything that does not fall into
// the above catagories.

#if defined(_WIN32) 
    #define OS                  OS_WIN32

    #if defined(_MSC_VER)
        #define COMP            COMP_MSVC
        #if defined(_M_IX86)
            #define ARCH        ARCH_IX86
        #elif defined(_M_ALPHA)
            #define ARCH        ARCH_ALPHA
        #else
            #error Unknown Win32 Architechture
        #endif
    #else
        #error _MSC_VER not defined.  MSVC is currently the only supported compiler
    #endif

#elif defined(_REDHAT)
    #define OS                  OS_REDHAT6  // TODO:dmb perhaps this should be just OS_REDHAT???
    #define COMP                COMP_GCC
    #if defined(_IX86)
        #define ARCH            ARCH_IX86
    #else
        #error Unknown Redhat Architechture
    #endif

#elif defined(_IRIX)
    #define OS                  OS_IRIX
    #define COMP                COMP_KAI_IRIX
    #define ARCH                ARCH_IRIX

#elif defined(_ALPHA)
    #define OS			        OS_OSF1
    #define COMP		        COMP_KAI_OSF1ALPHA
    #define ARCH		        ARCH_ALPHA

#elif defined(_SOLARIS)
    #define OS                  OS_SOLARIS
    #if defined(_IX86)
        #define COMP            COMP_SUNPRO
        #define ARCH            ARCH_IX86
    #else
        #define COMP            COMP_KAI_SUNPRO
        #define ARCH            ARCH_SPARC
    #endif

#elif defined(_AIX)
	#define OS					OS_AIX
	#define COMP				COMP_KAI_VISUALAGE
	#define ARCH				ARCH_RS6000

#elif defined (_HPUX)
	#define OS					OS_HPUX
	#define COMP				COMP_KAI_HPANSIC
	#define ARCH				ARCH_PARISC

#elif defined(__FreeBSD__)
    #define OS                  OS_BSD
    #define COMP                COMP_GCC
    #if defined(_IX86)
        #define ARCH            ARCH_IX86
    #else
        #define ARCH            ARCH_ALPHA	// is it really the #else?
    #endif

#elif defined(__OpenBSD__)
    #define OS                  OS_BSD
    #define COMP                COMP_GCC
    #if defined(_IX86)
        #define ARCH            ARCH_IX86
    #else
		// Wrong!  Somebody with OpenBSD fix this!
        #error "Architecture not known.  Please edit i386-unknown-openbsd.mak and platform.h"
	/* Other stuff that needs to be said */
    #endif /* defined(_IX86) */
#else
    #error Unknown OS
#endif

#if !defined(OS)
    #error OS definition did not resolve.  Check "platform.h".
#endif
#if !defined(ARCH)
    #error ARCH definition did not resolve.  Check "platform.h".
#endif
#if !defined(COMP)
    #error COMP definition did not resolve.  Check "platform.h".
#endif

//=============================================================================
// Platform Macros (a.k.a. "IS_" macros)
//
// These macros are the "worker bees" of platform.h.  Programmers should use
// these macros rather than comparing PLATFORM to the unique IDs by hand.
//
// NB: Programmers are STRONGLY ENCOURAGED not to use the OS detection macros or 
// the Architecture detection marcros directly.  Instead they should create 
// macros specific to the task at hand.  For example Win32 and Solaris support
// extended permissions for their files.  Rather than check IS_WIN32 || IS_SOLARIS,
// create a new macro called "HAS_EXTENDED_FILE_PERMISSIONS" and use that.
//
// One case where it is reasonable to use the IS_WIN32 or IS_UNIX is when
// you need to protect a #include that is specific to a platform.
//
// Example usage:
//
// #if IS_LITTLE_ENDIAN  // note this is not an "#ifdef"
// int network_order = swap(machine_order);
// #else
// int network_order = machine_order;
// #endif

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

// OS detection 
// Note: Avoid using these if possible (see above)
#define IS_WIN32    (OS == OS_WIN32)
#define IS_SOLARIS  (OS == OS_SOLARIS)
#define IS_LINUX    (OS == OS_REDHAT5 || OS == OS_REDHAT6 || OS == OS_SLACKWARE)
#define IS_UNIX     (OS == OS_REDHAT5 || OS == OS_REDHAT6 || OS == OS_SLACKWARE || OS == OS_SOLARIS || OS == OS_AIX || OS == OS_HPUX || OS == OS_IRIX || OS == OS_OSF1 || OS == OS_BSD)
#define IS_AIX		(OS == OS_AIX)
#define IS_HPUX		(OS == OS_HPUX)
#define IS_IRIX		(OS == OS_IRIX)
#define IS_OSF1		(OS == OS_OSF1)
#define IS_BSD		(OS == OS_BSD)

// Architecture detection
// Note: Avoid using these if possible (see above)
#define IS_IX86     (ARCH == ARCH_IX86)
#define IS_SPARC    (ARCH == ARCH_SPARC)
#define IS_ALPHA    (ARCH == ARCH_ALPHA)
#define IS_RS6000	(ARCH == ARCH_RS6000)
#define IS_PARISC	(ARCH == ARCH_PARISC)
#define IS_ALPHA	(ARCH == ARCH_ALPHA)

// complier detection
#define IS_KAI      (COMP == COMP_KAI_GCC || COMP == COMP_KAI_SUNPRO || COMP == COMP_KAI_GLIBC || COMP == COMP_KAI_VISUALAGE || COMP == COMP_KAI_HPANSIC || COMP == COMP_KAI_IRIX || COMP == COMP_KAI_OSF1ALPHA)
#define IS_MSVC     (COMP == COMP_MSVC)
#define IS_SUNPRO   (COMP == COMP_SUNPRO)
#define IS_GCC      (COMP == COMP_GCC)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

// Integer representation
#define USES_1S_COMPLEMENT      0       
#define USES_2S_COMPLEMENT      1       // all of our current platforms use 2's complement
#define USES_SIGNED_MAGNITUDE   0

// Byte allignment
#define IS_BYTE_ALLIGNED        1       // true if byte allignment is 8 bits (true for all current platforms)

// Endian detection
#define IS_LITTLE_ENDIAN        (IS_IX86 || IS_ALPHA)
#define IS_BIG_ENDIAN           (!IS_LITTLE_ENDIAN)

// Unicode
#define SUPPORTS_UNICODE        IS_WIN32    // The OS supports Unicode

// KAI 3.4 uses a much improved stl
#define IS_KAI_3_4              (IS_KAI && (COMP == COMP_KAI_IRIX || COMP == COMP_KAI_OSF1ALPHA || COMP == COMP_KAI_GLIBC))

// Used in twlocale
#define USE_STD_CPP_LOCALE_WORKAROUND (IS_SUNPRO || (IS_KAI && !IS_KAI_3_4))  // TODO:BAM -- name this something more general.
#define USE_CLIB_LOCALE         IS_KAI || IS_GCC
#define USES_CLIB_DATE_FUNCTION ( USE_CLIB_LOCALE || IS_SUNPRO || IS_MSVC ) // if we use clib, can't use C++ time_put, and SUNPRO and MSVC add characters
//#define USE_CLIB_LOCALE         (IS_ALPHA || IS_IRIX || (IS_KAI && !IS_KAI_3_4))

// Threading API
// TODO:mdb -- this is not complete or rigorous on the unix side!!! 
#define SUPPORTS_WIN32_THREADS	IS_WIN32
#define SUPPORTS_POSIX_THREADS	(!SUPPORTS_WIN32_THREADS)

// Miscellaneous
#define FSEEK_TAKES_INT32       IS_UNIX     // True if fseek takes 32-bit offsets
#define USE_OUTPUT_DEBUG_STRING IS_WIN32    // Use the Win32 OutputDebugString() for debug messages.
#define SUPPORTS_MAPI           IS_WIN32
#define WCHAR_IS_16_BITS        IS_WIN32
#define WCHAR_IS_32_BITS        IS_UNIX
#define WCHAR_REP_IS_UCS2       IS_WIN32
#define USES_MPOPEN             IS_UNIX
#define USES_WINSOCK            IS_WIN32
#define USES_BIN_DATE           IS_UNIX
#define SUPPORTS_WCHART         IS_WIN32    // TODO: Remove after getting new ver of KAI
#define USES_GLIBC              ((COMP == COMP_KAI_GLIBC) || IS_GCC)
#define SUPPORTS_SYSLOG         IS_UNIX
#define SUPPORTS_EVENTLOG       IS_WIN32
#define HAS_ICONV               IS_UNIX && ( ! IS_LINUX && ! IS_BSD)
#define SUPPORTS_MEMBER_TEMPLATES               ( ! IS_SUNPRO )
#define SUPPORTS_EXPLICIT_TEMPLATE_FUNC_INST    ( ! IS_SUNPRO )

//=============================================================================
// FHS -- Filesystem Hierarchy Standard Support
//
// If this is defined, then tripwire is being installed using the FHS. The only
// behavioral change that results from this is the default location that 
// Tripwire looks for its config file.
//
// (*) If following FHS: default config file location is /etc/tripwire/tw.cfg
// (*) If not: default is <tw-exe-dir>/tw.cfg 
//       where <tw-exe-dir> is the directory the tripwire executable is located in.
//=============================================================================
#define USES_FHS 				IS_LINUX

//=============================================================================
// Miscellaneous
//
// Put all items that are not an "IS_" macro here.  

#if IS_BYTE_ALLIGNED            
    #define BYTE_ALIGN      8
#else
    #error  Unknown Byte allignment
#endif

// A scalar that matches the sizeof a pointer
typedef unsigned long ptr_size_type;    // true for all of our current platforms
                                        // TODO: I would like to use a XXXX_t like name

// Check integer representation
#if !(USES_2S_COMPLEMENT)
    #error "Tripwire will only work on a 2's complement CPU.  Check \"platform.h\"."
#endif




#endif // __PLATFORM_H

