/*
 * Copyright (c) 1999
 * Silicon Graphics Computer Systems, Inc.
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
// WARNING: This is an internal header file, included by other C++
// standard library headers.  You should not attempt to use this header
// file directly.


#ifndef __SGI_STL_INTERNAL_CODECVT_H
#define __SGI_STL_INTERNAL_CODECVT_H

#include <stl/c_locale.h>
#include <stl/_locale.h>

__STL_BEGIN_NAMESPACE

class __STL_CLASS_DECLSPEC codecvt_base {
public:
  enum result {ok, partial, error, noconv};
};

template <class _InternT, class _ExternT, class _StateT>
class __STL_CLASS_DECLSPEC codecvt {};
 
template <class _InternT, class _ExternT, class _StateT>
class __STL_CLASS_DECLSPEC codecvt_byname {};

__STL_TEMPLATE_NULL
class __STL_CLASS_DECLSPEC codecvt<char, char, mbstate_t>
  : public locale::facet, public codecvt_base 
{
  friend class _Locale_impl;
#if defined(__MRC__) || defined(__SC__)	//*TY 04/29/2000 - added workaround for mpw
  typedef locale::facet _facet;			//*TY 04/29/2000 - they forget to look into nested class for the ctor.
#endif									//*TY 04/29/2000 - 
public:
  typedef char       intern_type;
  typedef char       extern_type;
  typedef mbstate_t  state_type;

  explicit codecvt(size_t __refs = 0);

  result out(mbstate_t    __state,
             const char*  __from,
             const char*  __from_end,
             const char*& __from_next,
             char*        __to,
             char*        __to_limit, 
             char*&       __to_next) const {
    return do_out(__state, 
                  __from, __from_end, __from_next,
                  __to,   __to_limit, __to_next);
  }

  result unshift(mbstate_t& __state,
                 char* __to, char* __to_limit, char*& __to_next) const
    { return do_unshift(__state, __to, __to_limit, __to_next); }
    
  result in(mbstate_t&   __state,
            const char*  __from,
            const char*  __from_end,  
            const char*& __from_next,
            char*        __to, 
            char*        __to_limit, 
            char*&       __to_next) const {
    return do_in(__state,
                 __from, __from_end, __from_next,
                 __to,   __to_limit, __to_next);
  }

  int encoding() const __STL_NOTHROW { return do_encoding(); }

  bool always_noconv() const __STL_NOTHROW { return do_always_noconv(); }

  int length(const mbstate_t& __state,
             const char* __from, const char* __end,
             size_t __max) const
    { return do_length(__state, __from, __end, __max); }
  
  int max_length() const __STL_NOTHROW { return do_max_length(); }

  __STL_STATIC_MEMBER_DECLSPEC static locale::id id;

protected:
  ~codecvt();

  virtual result do_out(mbstate_t&   /* __state */,
                        const char*  __from,
                        const char*  /* __from_end */,
                        const char*& __from_next,
                        char*        __to,
                        char*        /* __to_limit */,
                        char*&       __to_next) const;

  virtual result do_in (mbstate_t&   /* __state */ , 
                        const char*  __from,
                        const char*  /* __from_end */,
                        const char*& __from_next,
                        char*        __to,
                        char*        /* __to_end */,
                        char*&       __to_next) const;

  virtual result do_unshift(mbstate_t& /* __state */,
                            char*      __to,
                            char*      /* __to_limit */,
                            char*&     __to_next) const;

  virtual int do_encoding() const __STL_NOTHROW;
  virtual bool do_always_noconv() const __STL_NOTHROW;
  virtual int do_length(const mbstate_t&         __state,
                        const  char* __from, 
                        const  char* __end,
                        size_t __max) const;
  virtual int do_max_length() const __STL_NOTHROW;
private:
  codecvt(const codecvt<char, char, mbstate_t>&);
  codecvt<char, char, mbstate_t>& operator =(const codecvt<char, char, mbstate_t>&); 
};

# ifndef __STL_NO_WCHAR_T
 
__STL_TEMPLATE_NULL
class __STL_CLASS_DECLSPEC codecvt<wchar_t, char, mbstate_t>
  : public locale::facet, public codecvt_base
{
  friend class _Locale_impl;
#if defined(__MRC__) || defined(__SC__)	//*TY 04/29/2000 - added workaround for mpw
  typedef locale::facet _facet;			//*TY 04/29/2000 - they forget to look into nested class for the ctor.
#endif									//*TY 04/29/2000 - 
public:
  typedef wchar_t    intern_type;
  typedef char       extern_type;
  typedef mbstate_t  state_type;

  explicit codecvt(size_t __refs = 0);

  result out(mbstate_t       __state,
             const wchar_t*  __from,
             const wchar_t*  __from_end,
             const wchar_t*& __from_next,
             char*           __to,
             char*           __to_limit,
             char*&          __to_next) const {
    return do_out(__state,
                  __from, __from_end, __from_next, 
                  __to,   __to_limit, __to_next);
  }

  result unshift(mbstate_t& __state,
                 char*  __to, char*  __to_limit, char*& __to_next) const {
    return do_unshift(__state, __to, __to_limit, __to_next);
  }
    
  result in(mbstate_t    __state,
            const char*  __from,
            const char*  __from_end,  
            const char*& __from_next,
            wchar_t*     __to, 
            wchar_t*     __to_limit, 
            wchar_t*&    __to_next) const {
    return do_in(__state, 
                 __from, __from_end, __from_next,
                 __to,  __to_limit, __to_next);
  }

  int encoding() const __STL_NOTHROW { return do_encoding(); }

  bool always_noconv() const __STL_NOTHROW { return do_always_noconv(); }

  int length(const mbstate_t&        __state,
             const char* __from,
             const char* __end,
             size_t             __max) const
    { return do_length(__state, __from, __end, __max); }
  
  int max_length() const __STL_NOTHROW { return do_max_length(); }

  __STL_STATIC_MEMBER_DECLSPEC static locale::id id;

protected:
  ~codecvt();

  virtual result do_out(mbstate_t&         __state,
                        const wchar_t*  __from,
                        const wchar_t*  __from_end,
                        const wchar_t*& __from_next,
                        char*        __to,
                        char*        __to_limit,
                        char*&       __to_next) const;

  virtual result do_in (mbstate_t&         __state,
                        const char*  __from,
                        const char*  __from_end,
                        const char*& __from_next,
                        wchar_t*        __to,
                        wchar_t*        __to_limit,
                        wchar_t*&       __to_next) const;

  virtual result do_unshift(mbstate_t&   __state,
                            char*  __to, 
                            char*  __to_limit,
                            char*& __to_next) const;

  virtual int do_encoding() const __STL_NOTHROW;

  virtual bool do_always_noconv() const __STL_NOTHROW;
  
  virtual int do_length(const mbstate_t& __state,
                        const  char* __from, 
                        const  char* __end,
                        size_t __max) const;

  virtual int do_max_length() const __STL_NOTHROW;

private:
  codecvt(const codecvt<wchar_t, char, mbstate_t>&);
  codecvt<wchar_t, char, mbstate_t>& operator = (const codecvt<wchar_t, char, mbstate_t>&);  
};

# endif

__STL_TEMPLATE_NULL
class __STL_CLASS_DECLSPEC codecvt_byname<char, char, mbstate_t>
  : public codecvt<char, char, mbstate_t> {
public:
  explicit codecvt_byname(const char* __name, size_t __refs = 0);
private:
  codecvt_byname(const codecvt_byname<char, char, mbstate_t>&);
  codecvt_byname<char, char, mbstate_t>& operator =(const codecvt_byname<char, char, mbstate_t>&);  
};

# ifndef __STL_NO_WCHAR_T
__STL_TEMPLATE_NULL
class codecvt_byname<wchar_t, char, mbstate_t>
  : public codecvt<wchar_t, char, mbstate_t> 
{
public:
  explicit codecvt_byname(const char * __name, size_t __refs = 0);    

protected:
  ~codecvt_byname();

  virtual result do_out(mbstate_t&         __state,
                        const wchar_t*  __from,
                        const wchar_t*  __from_end,
                        const wchar_t*& __from_next,
                        char*        __to,
                        char*        __to_limit,
                        char*&       __to_next) const;

  virtual result do_in (mbstate_t&         __state,
                        const char*  __from,
                        const char*  __from_end,
                        const char*& __from_next,
                        wchar_t*        __to,
                        wchar_t*        __to_limit,
                        wchar_t*&       __to_next) const;

  virtual result do_unshift(mbstate_t&   __state,
                            char*  __to, 
                            char*  __to_limit,
                            char*& __to_next) const;

  virtual int do_encoding() const __STL_NOTHROW;

  virtual bool do_always_noconv() const __STL_NOTHROW;
  
  virtual int do_length(const mbstate_t&         __state,
                        const  char* __from, 
                        const  char* __end,
                        size_t __max) const;

  virtual int do_max_length() const __STL_NOTHROW;

private:
  _Locale_ctype* _M_ctype;
  codecvt_byname(const codecvt_byname<wchar_t, char, mbstate_t>&);
  codecvt_byname<wchar_t, char, mbstate_t>& operator =(const codecvt_byname<wchar_t, char, mbstate_t>&);  
};

# endif

__STL_END_NAMESPACE

#endif /* __SGI_STL_INTERNAL_CODECVT_H */

// Local Variables:
// mode:C++
// End:

