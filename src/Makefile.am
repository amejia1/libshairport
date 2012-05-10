lib_LTLIBRARIES=libshairport.la

library_includedir=$(includedir)/shairport
library_include_HEADERS = shairport.h

noinst_HEADERS = alac.h hairtunes.h socketlib.h shairport_private.h

libshairport_la_SOURCES=shairport.c hairtunes.c socketlib.c alac.c
libshairport_la_CFLAGS=-Wl,--no-undefined 
libshairport_la_LDFLAGS=-version-info @LIBSHAIRPORT_LIBTOOL_VERSION@
