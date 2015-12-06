libdir           = $(plugindir)
lib_LTLIBRARIES  = skype.la

skype_la_CFLAGS  = $(BITLBEE_CFLAGS) $(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS)
skype_la_LDFLAGS = $(BITLBEE_LIBS)   $(GLIB_LIBS)   $(LIBGCRYPT_LIBS)
skype_la_SOURCES = \
	skype.c

# Build the library as a module
skype_la_LDFLAGS += -module -avoid-version
