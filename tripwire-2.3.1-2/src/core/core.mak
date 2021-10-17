#
# core.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = core
TYPE = LIBRARY

##### Additional Objects #####
# These source files are in a sub-directory, but the resultant object files end up 
# in the same place as the object files constructed from source files that are not
# in a sub-directory.  Therefore the rule for these object files is slightly
# different and must be specified explicitly.
# This can probably be removed with a bit of directory re-structuring

ADD_OBJS = file_unix.o unixfsservices.o
ADD_SRCS = unix/file_unix.cpp unix/unixfsservices.cpp

$(OBJDIR)/file_unix.o :
	$(CXX) -o $(OBJDIR)/file_unix.o $(CXXFLAGS) $(DEFINES) -c unix/file_unix.cpp
$(OBJDIR)/unixfsservices.o :
	$(CXX) -o $(OBJDIR)/unixfsservices.o $(CXXFLAGS) $(DEFINES) -c unix/unixfsservices.cpp

##### End Additional Objects #####

DSP_OBJS = charutil_t.o displayencoder_t.o archive.o charutil.o cmdlineparser.o codeconvert.o core.o coreerrors.o corestrings.o crc32.o debug.o displayencoder.o displayutil.o error.o errorbucketimpl.o errortable.o errorutil.o fileerror.o fileheader.o fsservices.o growheap.o hashtable.o haval.o md5.o msystem.o ntmbs.o objectpool.o refcountobj.o serializable.o serializer.o serializerimpl.o serializerutil.o serstring.o sha.o srefcountobj.o srefcounttbl.o stdcore.o stringutil.o timebomb.o timeconvert.o tw_signal.o twlimits.o twlocale.o unixexcept.o usernotify.o usernotifystdout.o utf8.o wchar16.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)
SRCS =  $(DSP_SRCS) $(ADD_SRCS)

include ../make_include/common_rules.mak
