#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([odp-daq-module], [0.1], [maxim.uvarov@linaro.org])
AM_INIT_AUTOMAKE([daq], [0.1])
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

# Substitutions

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
