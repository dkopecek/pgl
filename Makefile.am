ACLOCAL_AMFLAGS= -I m4

EXTRA_DIST=\
	README.md \
	LICENSE

AM_CPPFLAGS=\
	-I$(top_srcdir)/src

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libpgl.pc

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
	src/Library/Message.cpp \
	src/Library/Utility.hpp \
	src/Library/Utility.cpp \
	src/Library/Logger.cpp

pkginclude_HEADERS=\
	src/Library/Group.hpp \
	src/Library/Process.hpp \
	src/Library/Message.hpp \
	src/Library/pgl.hpp \
	src/Library/Exceptions.hpp \
	src/Library/Timeout.hpp \
	src/Library/Logger.hpp

bin_PROGRAMS=\
	test \
	minprivs \
	fd-send-recv \
	signals

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

fd_send_recv_SOURCES=\
	src/Examples/fd-send-recv.cpp

fd_send_recv_CPPFLAGS=\
	-I$(top_srcdir)/src/Library

fd_send_recv_LDADD=\
	$(top_builddir)/libpgl.la

signals_SOURCES=\
	src/Examples/signals.cpp

signals_CPPFLAGS=\
	-I$(top_srcdir)/src/Library

signals_LDADD=\
	$(top_builddir)/libpgl.la



