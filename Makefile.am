SUBDIRS = include

lib_LTLIBRARIES = libmyD.la

libmyD_la_SOURCES = p_libmyD.h \
	pem.c structure.c traverse.c policy.c debug.c

libmyD_la_LDFLAGS = -avoid-version

bin_PROGRAMS = myd-verify

myd_verify_SOURCES = verify.c

myd_verify_LDADD = libmyD.la
