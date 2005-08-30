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

#
# The rest of the Makefile contains targets for various video conversions.
#
# This next line stops make from deleting intermediate files.

.SECONDARY:

# First, various audio conversions.  MP3 is the more compact format
# with all the patent issues surrounding it.  MP2 is the bulkier
# format that doesn't seem to have patent problems.
#
# '.pcm' files are raw 16-bit ?-endian mono 48kHz produced by sndkit's vrec:
#	vrec -s 48000 -b 16 -r audio.pcm
# '.pcs' files are the same thing, but stereo (add '-S' switch to vrec)

%.mp2: %.pcm
	toolame -m mono -s 48 $< $@
%.mp2: %.pcs
	toolame -m stereo -s 48 $< $@

%.mp3: %.pcm
	lame -m mono -rx -s 48 $< $@
%.mp3: %.pcs
	lame -m stereo -rx -s 48 $< $@

# Targets to create DVD-standard MPEG-2 video (MP2 audio) using
# mjpegtools's mpeg2enc.  I don't use mpeg2enc much anymore; ffmpeg
# seems to produce smaller files, but I still use ppmtoy4m and
# yuvscaler, both from mjpegtools.
#
#%.mpv: %.fbs
#	rfbproxy -x $< | ppmtoy4m -S 420_jpeg | yuvscaler -n ntsc -O DVD | \
#		mpeg2enc -f 8 -q 1 -o $@
#%.dvd: %.mpv %.mp2
#	mplex -f 8 -o $@ $^

# Targets to create DVD-standard 720x480 MPEG-2 video (MP2 audio) using ffmpeg
#
# The use of the '.dvd' file extension is crucial if you want NAV packs.
# These '.dvd' files can be handled as-is by dvdauthor(1).
#
# An '.ffbs' file differs from an '.fbs' file only in that the screen
# was rotated 180 degrees when the capture occured, so we need to
# 'ppmflip' it so it isn't upside down.  (I know, I'm the only person
# who uses this.)

%.dvd: %.fbs %.mp2
	rfbproxy -x $*.fbs | ppmtoy4m -S 420_jpeg | \
	    yuvscaler -n ntsc -O DVD -v 0 | \
	    ffmpeg -target dvd -f yuv4mpegpipe -i - -i $*.mp2 -acodec copy $@
%.dvd: %.ffbs %.mp2
	rfbproxy -x $*.ffbs | ppmflip | ppmtoy4m -S 420_jpeg | \
	    yuvscaler -n ntsc -O DVD -v 0 | \
	    ffmpeg -target dvd -f yuv4mpegpipe -i - -i $*.mp2 -acodec copy $@


# These targets build unscaled DivX6-compatible MPEG-4/MP3 AVI files.
# DivX6 doesn't seem to come with MP2 support, so I use MP3.  ffmpeg's
# man page explains its flags.

%.avi: %.fbs %.mp3
	rfbproxy -x $*.fbs | ppmtoy4m -S 420_jpeg | \
	    ffmpeg -f yuv4mpegpipe -i - -i $*.mp3 \
		-vcodec mpeg4 -vtag DivX -b 800 -g 300 -bf 2 -acodec copy $@
%.avi: %.ffbs %.mp3
	rfbproxy -x $*.ffbs | ppmflip | ppmtoy4m -S 420_jpeg | \
	    ffmpeg -f yuv4mpegpipe -i - -i $*.mp3 \
		-vcodec mpeg4 -vtag DivX -b 800 -g 300 -bf 2 -acodec copy $@

# Targets for DivX6-compatible MPEG-4/MP3 AVI scaled to 720x480 (DVD size)

%-720x480.avi: %.fbs %.mp3
	rfbproxy -x $*.fbs | ppmtoy4m -S 420_jpeg | \
	    yuvscaler -n ntsc -O DVD -v 0 | \
	    ffmpeg -f yuv4mpegpipe -i - -i $*.mp3 \
		-vcodec mpeg4 -vtag DivX -b 800 -g 300 -bf 2 -acodec copy $@
%-720x480.avi: %.ffbs %.mp3
	rfbproxy -x $*.ffbs | ppmflip | ppmtoy4m -S 420_jpeg | \
	    yuvscaler -n ntsc -O DVD -v 0 | \
	    ffmpeg -f yuv4mpegpipe -i - -i $*.mp3 \
		-vcodec mpeg4 -vtag DivX -b 800 -g 300 -bf 2 -acodec copy $@

# I don't know how to get ffmpeg2theora to take both an audio and a
# video file as input, so this next rule only builds video.  I don't
# use it.

#%.ogg: %.fbs
#	rfbproxy -x $< | ppmtoy4m -S 420_jpeg | \
#	    yuvscaler -n ntsc -O DVD -v 0 | \
#	    ffmpeg2theora -f yuv4mpegpipe -o $@ -

# Instead I use this rule, which converts the MPEG-4 AVI file to
# OGG/Theora.  Takes longer, but it's the only way I know how to get
# both audio and video into an Ogg file.
#
# Note that you can request either file.ogg or file-720x480.ogg

%.ogg: %.avi
	ffmpeg2theora -o $@ $<
