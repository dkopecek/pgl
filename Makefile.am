ACLOCAL_AMFLAGS= -I m4

AM_CPPFLAGS=\
	-I$(top_srcdir)/src

lib_LTLIBRARIES=\
	libpgl.la

libpgl_la_CPPFLAGS=\
	-I$(top_srcdir)/src
#	@sodium_CFLAGS@

libpgl_la_LDFLAGS=\
	-no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

#libpgl_la_LIBADD=\
#	@sodium_LIBS@

libpgl_la_SOURCES=\
	src/Library/Group.hpp \
	src/Library/Group.cpp \
	src/Library/Process.hpp \
	src/Library/Process.cpp \
	src/Library/Message.hpp \
	src/Library/Message.cpp

bin_PROGRAMS=\
	test \
	minprivs

test_SOURCES=\
	src/Examples/test.cpp

test_CPPFLAGS=\
	-I$(top_srcdir)/src/Library

test_LDADD=\
	$(top_builddir)/libpgl.la

minprivs_SOURCES=\
	src/Examples/minprivs.cpp

minprivs_CPPFLAGS=\
	-I$(top_srcdir)/src/Library

minprivs_LDADD=\
	$(top_builddir)/libpgl.la \
	-lseccomp -lcap-ng
