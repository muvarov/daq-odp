#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([daq], [0.1], [maxim.uvarov@linaro.org])
AM_INIT_AUTOMAKE()
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([daq_odp.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Enable visibility if we can
AC_ENABLE_VISIBILITY()
# Special compiler flags for ICC, etc.
AC_SF_COMPILER_SETUP()

# Checks for the DAQ API headers and the SFBPF headers/library.
AC_CHECK_DAQ_API
AC_CHECK_SFBPF

# Checks for other dependencies of your DAQ module go here.


# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h odp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strdup strerror strtol])
AC_SEARCH_LIBS([timer_createm],[rt posix4])

AC_ARG_WITH([odp-path],
AC_HELP_STRING([--with-odp-path=DIR Path to odp libs and headers],
               [(or in the default path if not specified).]),
[ODP_PATH=$withval
CFLAGS="$CFLAGS -I$ODP_PATH/include -I$ODP_PATH/include/helper"
LDFLAGS="$LDFLAGS -L$ODP_PATH/lib"
],[])
# Substitutions

AC_SUBST([LIBS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION
	========


	compiler:		${CC}
	cflags:			${CFLAGS}
	am_cflags:		${AM_CFLAGS}
	ldflags:		${LDFLAGS}
	am_ldflags:		${AM_LDFLAGS}

])
