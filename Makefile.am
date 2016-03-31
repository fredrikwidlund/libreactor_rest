ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4
AM_CFLAGS = -std=gnu11 -O3 -flto -fuse-linker-plugin -I$(srcdir)/src/picohttpparser
AM_LDFLAGS = -static

SOURCE_FILES = \
src/reactor_rest/reactor_rest.c

HEADER_FILES = \
src/reactor_rest/reactor_rest.h

MAIN_HEADER_FILES = \
src/reactor_rest.h

AUTOMAKE_OPTIONS = subdir-objects
lib_LTLIBRARIES = libreactor_rest.la
libreactor_rest_la_SOURCES =  $(SOURCE_FILES) $(HEADER_FILES)

headerfilesdir = $(includedir)/reactor_rest
headerfiles_HEADERS = $(HEADER_FILES)

mainheaderdir = $(includedir)
mainheader_HEADERS = $(MAIN_HEADER_FILES)

MAINTAINERCLEANFILES = aclocal.m4 config.h.in configure Makefile.in libreactor_rest-?.?.?.tar.gz
maintainer-clean-local:; rm -rf autotools m4 libreactor_rest-?.?.?
