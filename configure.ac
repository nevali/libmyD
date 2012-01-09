AC_INIT([libmyD],[develop])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE
AC_PROG_LIBTOOL

developer_CPPFLAGS='-W -Wall -Wno-deprecated-declarations -g'

if test x"$VERSION" = x"develop" ; then
   AC_MSG_RESULT([enabling developer-mode CPPFLAGS: $developer_CPPFLAGS])
   CPPFLAGS="$CPPFLAGS $developer_CPPFLAGS"
fi

AC_PROG_CC

PKG_CHECK_MODULES([libcrypto],[libcrypto >= 0.9.8],[
	CPPFLAGS="$CPPFLAGS $libcrypto_CFLAGS"
	LIBS="$LIBS $libcrypto_LIBS"
],[AC_MSG_ERROR([cannot find OpenSSL's libcrypto using pkg-config; please ensure both pkg-config and OpenSSL development files are present, and if necessary set the PKG_CONFIG_PATH environment variable.])])

PKG_CHECK_MODULES([redland],[redland >= 1.0.7],[
	CPPFLAGS="$CPPFLAGS $redland_CFLAGS"
	LIBS="$LIBS $redland_LIBS"
],[AC_MSG_ERROR([cannot find Redland using pkg-config; please ensure both pkg-config and Redland development files are present, and if necessary set the PKG_CONFIG_PATH environment variable.])])

CPPFLAGS="$CPPFLAGS -I\${top_srcdir}/include -I\${top_builddir}/include"

AC_SUBST([CPPFLAGS])
AC_SUBST([LIBS])

AC_CHECK_HEADERS([unistd.h])
AC_HEADER_TIME
AC_CHECK_FUNCS([isatty _isatty])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
Makefile
include/Makefile
include/myD/Makefile
])

AC_OUTPUT


