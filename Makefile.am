AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = rfbproxy
man_MANS = rfbproxy.1

rfbproxy_SOURCES = rfbproxy.c

EXTRA_DIST = $(man_MANS) autogen.sh rfbproxy.spec.in rfbproxy.spec

TESTS_ENVIRONMENT = top_srcdir=$(top_srcdir) top_builddir=$(top_builddir)
TESTS = tests/run-tests

update:
	@cvs -nq update | grep -q . && \
	( echo "*** Local files are modified!"; \
	  exit 1 ) || exit 0

tag:
	cvs tag -c `echo V@VERSION@ | tr . _`
