/*
 * Copyright (c) 1994
 * Hewlett-Packard Company
 *
 * Copyright (c) 1996,1997
 * Silicon Graphics Computer Systems, Inc.
 *
 * Copyright (c) 1997
 * Moscow Center for SPARC Technology
 *
 * Copyright (c) 1999 
 * Boris Fomitchev
 *
 * This material is provided "as is", with absolutely no warranty expressed
 * or implied. Any use is at your own risk.
 *
 * Permission to use or copy this software for any purpose is hereby granted 
 * without fee, provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 *
 */

/* NOTE: This is an internal header file, included by other STL headers.
 *   You should not attempt to use it directly.
 */

#ifndef __SGI_STL_HASHTABLE_H
#define __SGI_STL_HASHTABLE_H

# ifndef __STL_OUTERMOST_HEADER_ID
#  define __STL_OUTERMOST_HEADER_ID 0xa011
#  include <stl/_prolog.h>
# endif

#ifndef __SGI_STL_ALGO_H
#include <algo.h>
#endif
#ifndef __SGI_STL_ALLOC_H
#include <alloc.h>
#endif
#ifndef __SGI_STL_VECTOR_H
#include <vector.h>
#endif
#ifndef __SGI_STL_HASH_FUN_H
#include <stl/_hash_fun.h>
#endif
#ifndef __SGI_STL_INTERNAL_HASHTABLE_H
#include <stl/_hashtable.h>
#endif

#ifdef __STL_USE_NAMESPACES
# ifdef __STL_BROKEN_USING_DIRECTIVE
using namespace STLPORT;
# else
using __STLPORT_STD::hash;
using STLPORT::hashtable;
# endif
#endif /* __STL_USE_NAMESPACES */

# if (__STL_OUTERMOST_HEADER_ID == 0xa011)
#  include <stl/_epilog.h>
#  undef __STL_OUTERMOST_HEADER_ID
# endif
#endif /* __SGI_STL_HASHTABLE_H */

// Local Variables:
// mode:C++
// End:
