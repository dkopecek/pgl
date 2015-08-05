AC_PREREQ([2.69])
AC_INIT([pgl], [0.1], [dkopecek@redhat.com])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([src/build-config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([config])

AM_INIT_AUTOMAKE([subdir-objects foreign tar-pax])

# If automake supports "silent rules", enable them by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

#
# Compiler flags
#
CXXFLAGS="-std=c++11 -Wall -Wformat=2 $CXXFLAGS"

#
# Additional CXXFLAGS used when --enable-debug-build is used
#
CXXFLAGS_DEBUG_ENABLED="-g -O0"

#
# Additional CXXFLAGS used when --disable-debug-build is used
#
# Don't add -DNDEBUG here. It's added to the generated config.h
# header file.
#
CXXFLAGS_DEBUG_DISABLED=""

#
# Additional CXXFLAGS used when --enable-optimized-build is used
#
CXXFLAGS_OPTIMIZED_BUILD="-O2 -ffast-math -fomit-frame-pointer"

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL
AC_PROG_LIBTOOL

# libtool versioning
# See http://sources.redhat.com/autobook/autobook/autobook_91.html#SEC91 for details

## increment if the interface has additions, changes, removals.
LT_CURRENT=0

## increment any time the source changes; set 0 to if you increment CURRENT
LT_REVISION=0

## increment if any interfaces have been added; set to 0
## if any interfaces have been changed or removed. removal has
## precedence over adding, so set to 0 if both happened.
LT_AGE=0

AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

# Check for libraries
#PKG_CHECK_MODULES([sodium], [libsodium >= 0.4.5], [],
#                  AC_MSG_FAILURE([libsodium development files not found!]))

# Checks for required header files.
AC_CHECK_HEADERS([\
assert.h \
errno.h \
fcntl.h \
limits.h \
signal.h \
stddef.h \
stdint.h \
string.h \
sys/prctl.h \
sys/resource.h \
sys/select.h \
sys/signalfd.h \
sys/socket.h \
sys/time.h \
sys/types.h \
sys/wait.h \
time.h \
unistd.h],[],[AC_MSG_ERROR([Some of the required header files were not found on your system!])])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([clock_gettime dup2 strdup])

# ./configure script options
AC_ARG_ENABLE([debug-build],
     [AC_HELP_STRING([--enable-debug-build], [enable debugging flags (default=no)])],
     [case "${enableval}" in
       yes) debug=yes ;;
       no)  debug=no ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug-build]) ;;
     esac], [debug=no])

AC_ARG_ENABLE([optimized-build],
              [AC_HELP_STRING([--enable-optimized-build], [enable optimized build (default=no)])],
              [case "${enableval}" in
                yes) optimized=yes ;;
                no) optimized=no ;;
                *) AC_MSG_ERROR([bad value ${enableval} for --enable-optimized-build]) ;;
               esac], [optimized=no])

if test "$debug" = "yes"; then
   CXXFLAGS="$CXXFLAGS $CXXFLAGS_DEBUG_ENABLED"
else
   CXXFLAGS="$CXXFLAGS $CXXFLAGS_DEBUG_DISABLED"
   AC_DEFINE([NDEBUG], [1], [Debug build disabled])
fi

if test "$optimized" = "yes"; then
  CXXFLAGS="$CXXFLAGS $CXXFLAGS_OPTIMIZED_BUILD"
  AC_DEFINE([OPTIMIZED], [1], [Optimized build])
fi

AC_CONFIG_FILES([Makefile libpgl.pc])
AC_OUTPUT
