AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = rfbproxy
man_MANS = rfbproxy.1

rfbproxy_SOURCES = rfbproxy.c

EXTRA_DIST = $(man_MANS) autogen.sh rfbproxy.spec.in rfbproxy.spec

test check: rfbproxy xclock.fbs windows.fbs
	#
	#             REGRESSION TESTS
	#
	# tests 1, 2, 3
	#   export a recorded session (rgb888 CoRRE) at different framerates
	#
	@echo -n "test 1... "; \
	if [ `./rfbproxy -x --framerate 1 xclock.fbs | md5sum | cut -c1-32`\
	     = 203ad5c8cfc365d03b25c5699e3866aa ]; then echo passed; \
	else echo FAILED; \
	fi
	@echo -n "test 2... "; \
	if [ `./rfbproxy -x --framerate 2 xclock.fbs | md5sum | cut -c1-32`\
	     = feb7a90f227ada6dc59c18eb228f77e9 ]; then echo passed; \
	else echo FAILED; \
	fi
	@echo -n "test 3... "; \
	if [ `./rfbproxy -x xclock.fbs | md5sum | cut -c1-32`\
	     = cb35b3f28b8f1d7465a02cc41cb14ac0 ]; then echo passed; \
	else echo FAILED; \
	fi
	#
	# test 4
	#   same as test 3, but at an absurdly large framerate ratio
	#
	@echo -n "test 4... "; \
	if [ `./rfbproxy -x --framerate 3000000:100100 xclock.fbs | md5sum | cut -c1-32`\
	     = cb35b3f28b8f1d7465a02cc41cb14ac0 ]; then echo passed; \
	else echo FAILED; \
	fi
	#
	# test 5
	#   export a session with a 16-bit pixel format (rgb565 hextile)
	#
	@echo -n "test 5... "; \
	if [ `./rfbproxy -x xclock2.fbs | md5sum | cut -c1-32`\
	     = 485315d52148726aabaf0806f4acbfd0 ]; then echo passed; \
	else echo FAILED; \
	fi
	#
	# tests 6, 7
	#   export a recorded Windows session (rgb888 hextile)
	#
	@echo -n "test 6... "; \
	if [ `./rfbproxy -x --framerate 1 windows.fbs | md5sum | cut -c1-32`\
	     = fbe828538ceda491cc26230cb5204b96 ]; then echo passed; \
	else echo FAILED; \
	fi
	@echo -n "test 7... "; \
	if [ `./rfbproxy -x windows.fbs | md5sum | cut -c1-32`\
	     = 4f66176c036200b4345a85c3ba98062b ]; then echo passed; \
	else echo FAILED; \
	fi

update:
	@cvs -nq update | grep -q . && \
	( echo "*** Local files are modified!"; \
	  exit 1 ) || exit 0

tag:
	cvs tag -c `echo V@VERSION@ | tr . _`
