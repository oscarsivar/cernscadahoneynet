/*
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

# if !defined (__STL_OUTERMOST_HEADER_ID)
#  define __STL_OUTERMOST_HEADER_ID 0x244
#  include <stl/_prolog.h>
# elif (__STL_OUTERMOST_HEADER_ID == 0x244) && ! defined (__STL_DONT_POP_0x244)
#  define __STL_DONT_POP_0x244
# endif

# if defined (__STL_HAS_NO_NAMESPACES) && ! defined (exception)
#  define exception __math_exception
# endif

# include __STL_NATIVE_C_HEADER(math.h)

# if defined (__STL_HAS_NO_NAMESPACES)
#  undef exception
# endif

# if (__STL_OUTERMOST_HEADER_ID == 0x244)
#  if ! defined (__STL_DONT_POP_0x244)
#   include <stl/_epilog.h>
#   undef  __STL_OUTERMOST_HEADER_ID
#   endif
#   undef  __STL_DONT_POP_0x244
# endif

// Local Variables:
// mode:C++
// End:
