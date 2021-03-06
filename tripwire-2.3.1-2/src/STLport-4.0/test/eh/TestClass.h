/***********************************************************************************
	TestClass.h
	
 * Copyright (c) 1997-1998
 * Mark of the Unicorn, Inc.
 *
 * Permission to use, copy, modify, distribute and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation.  Mark of the Unicorn makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
		
		SUMMARY: TestClass simulates a class that uses resources. It is designed to
			cause exceptions when it is constructed or copied.
		
***********************************************************************************/
#ifndef INCLUDED_MOTU_TestClass
#define INCLUDED_MOTU_TestClass 1

# include "Prefix.h"

# if defined (EH_NEW_HEADERS)
#  include <functional>
#  include <utility>
#  include <climits>
# else
#  include <function.h>
#  include <pair.h>
#  include <limits.h>
# endif


#include <iosfwd>
#include "random_number.h"
#include "nc_alloc.h"

class TestClass
{
public:
    inline TestClass();
    inline TestClass( int value );
    inline TestClass( const TestClass& rhs );
    inline ~TestClass();
    
    inline TestClass& operator=( const TestClass& rhs );
    inline int value() const;
	
    inline TestClass operator!() const;

    inline bool operator==( const TestClass& rhs ) const
  {
    return value() == rhs.value();
  }

protected:
    static inline unsigned int get_random(unsigned range = UINT_MAX);
private:
	inline void Init( int value );

#if TESTCLASS_DEEP_DATA
    int *p;
#else
	int v;
#endif
};

#if defined( __MWERKS__ ) && __MWERKS__ <= 0x3000 && !__SGI_STL
# if defined( __MSL__ ) && __MSL__ < 0x2406
#  include <iterator.h>
__MSL_FIX_ITERATORS__(TestClass);
__MSL_FIX_ITERATORS__(const TestClass);
typedef EH_STD::pair<const TestClass, TestClass> pair_testclass_testclass;
__MSL_FIX_ITERATORS__( pair_testclass_testclass );
__MSL_FIX_ITERATORS__( const pair_testclass_testclass );
# endif
#endif

inline void TestClass::Init( int value )
{
#if TESTCLASS_DEEP_DATA
	p = new int( value );
#else
	simulate_constructor();
	v = value;
#endif
}

inline TestClass::TestClass()
{
	Init( int(get_random()) );
}

inline TestClass::TestClass( int value )
{
	Init( value );
}

inline TestClass::TestClass( const TestClass& rhs )
{
	Init( rhs.value() );
}

inline TestClass::~TestClass()
{
#if TESTCLASS_DEEP_DATA
	delete p;
#else
	simulate_destructor();
#endif
}

inline TestClass& TestClass::operator=( const TestClass& rhs )
{
#if TESTCLASS_DEEP_DATA
	int *newP = new int( rhs.value() );
	delete p;
	p = newP;
#else
	simulate_possible_failure();
    v = rhs.value();
#endif
    return *this;
}

inline int TestClass::value() const
{
#if TESTCLASS_DEEP_DATA
	return *p;
#else
	return v;
#endif
}

inline TestClass TestClass::operator!() const
{
    return TestClass( value()+1 );
}

inline bool operator<( const TestClass& lhs, const TestClass& rhs ) {
    return lhs.value() < rhs.value();
}

inline bool operator>( const TestClass& lhs, const TestClass& rhs ) {
    return rhs < lhs;
}

inline bool operator>=( const TestClass& lhs, const TestClass& rhs ) {
    return !(lhs < rhs);
}

inline bool operator<=( const TestClass& lhs, const TestClass& rhs ) {
    return !(rhs < lhs);
}

# if 0
inline bool operator==( const TestClass& lhs, const TestClass& rhs )
{
    return lhs.value() == rhs.value();
}
# endif

inline bool operator != ( const TestClass& lhs, const TestClass& rhs ) {
    return lhs.value() != rhs.value();
}

inline unsigned int TestClass::get_random( unsigned range )
{
    return random_number( range );
}

# ifdef EH_NEW_IOSTREAMS
extern EH_STD::ostream& operator << ( EH_STD::ostream& s, const TestClass&);
# else
extern ostream& operator << ( ostream& s, const TestClass&);
# endif

#endif // INCLUDED_MOTU_TestClass
