/* rfbproxy - a record/playback VNC proxy
 * Copyright (C) 2000-3  Tim Waugh <twaugh@redhat.com>
 * Copyright (C) 2005  Brent Baccala <baccala@freesoft.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/*
 * rfbproxy is a program to record, playback, and export VNC sessions.
 * It derives its name both from the RFB protocol used by VNC, and
 * from Tim Waugh's original concept of a program to sit between a VNC
 * client and a VNC server, holding network connections to both and
 * copying the RFB protocol from one to the other while recording the
 * server-to-client traffic to a file.  rfbproxy can still be used in
 * this way, or it can be used in a shared-session mode, where it
 * implements a simple client that connects to a VNC server in shared
 * mode (i.e, simultaneously with other clients) and constantly
 * requests framebuffer updates, which it copies to a file.  After
 * recording a session, rfbproxy can either play it back to a VNC
 * client (the original concept), or export it as a series of PPM
 * frames suitable for further processing (conversion to MPEG video,
 * mainly).
 *
 * Since clients can send a message to the server requesting whatever
 * pixel format they please, a disadvantage of recording only the
 * server-to-client traffic is that you can never be quite sure what
 * pixel format the client has requested, and thus what format the
 * recorded file is in!  Worse, since part of the configurable pixel
 * format is the size of a pixel, you can never even be quite sure how
 * long a framebuffer update is.  The original FBS 1.0 file format
 * left this issue unaddressed.  FBS 1.1 is idential to FBS 1.0,
 * except that it demands the server's native pixel format to be used
 * throughout the recorded file.  FBS 1.1 files are created by a
 * shared-session record; FBS 1.0 files are still created by a proxy
 * record.
 *
 * If you want to play back an FBS 1.0 session to a VNC client, you
 * should playback with the same client used to record.  This yields
 * the best chances of the pixel format(s) in it matching what the
 * client will request during playback.  xvncviewer 3.3.7, for
 * example, requests first a small pixel format when it first
 * connects, then switches to a larger pixel format if the network
 * throughput seems acceptable.  A different client might not match
 * these changes exactly, and thus be unable to playback an FBS 1.0
 * session recorded with xvncviewer 3.3.7.
 *
 * FBS 1.1 playback is not without its problems, however.  rfbproxy
 * correctly translates to the pixel format the client requests, but
 * otherwise makes no attempt to understand the client messages.  In
 * particular, a client that was partially obscured and requests an
 * update to display a now-exposed region will find this request
 * ignored.  rfbproxy simply feeds the client the framebuffer updates
 * as they were recorded.
 *
 * On the other hand, if you want to export the recorded session as
 * PPM frames, then you almost certainly want FBS 1.1 (shared-session
 * record).  A proxy (FBS 1.0) session recorded from xvncviewer 3.3.7,
 * for example, would be unusable for PPM export due the
 * client-initiated changes to pixel format.
 *
 * Tim found that hextile encoding gives the best results.
 *
 * See also: the TODO file.
 */

/*
 * The FBS (framebuffer stream) file format is this:
 *
 * <capture file> ::- <version><data>
 * <version>      ::- 'FBS 001.000\n' | 'FBS 001.001\n'
 * <data>         ::- <byte-count><raw-data><timestamp><data>
 *                  | <byte-count><raw-data><timestamp>
 * <byte-count>   ::- 32-bit number of bytes, big-endian
 * <raw-data>     ::- data received at timestamp <timestamp>, which is
 *                    <byte-count> bytes in length, padded to multiple
 *                    of 32-bits
 * <timestamp>    ::- 32-bit number of milliseconds since beginning of
 *                    capture, big-endian
 *
 * Note that we don't capture any of the client messages (only the
 * server messages are saved).
 *
 * A zero byte-count packet is interpreted as EOF (timestamped).
 *
 * FBS 001.000 leaves the pixel format in the file unspecified
 * FBS 001.001 specify guarantees that the server's native
 *    pixel format (announced in the initialization) is used throughout
 *
 * The RFM (remote framebuffer macro) file format is documented here:
 * <URL:ftp://people.redhat.com/twaugh/rfbplaymacro/script-spec>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <setjmp.h>
#include <endian.h>

#if HAVE_STDINT_H
# include <stdint.h>
#else
# if HAVE_U_INTXX_T
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;
# else
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
# endif
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "d3des.h"

#define CHALLENGESIZE 16

/* This function ripped from vnc source as is (vncauth.c) */
void
vncEncryptBytes(unsigned char *bytes, unsigned char *passwd)
{
    unsigned char key[8];
    int i;

    /* key is simply password padded with nulls */

    for (i = 0; i < 8; i++) {
        if (i < strlen(passwd)) {
            key[i] = passwd[i];
        } else {
            key[i] = 0;
        }
    }

    deskey(key, EN0);

    for (i = 0; i < CHALLENGESIZE; i += 8) {
        des(bytes+i, bytes+i);
    }
}

#define VNC_BASE 5900
#define DEFAULT_DISPLAY ":10"
#define DEFAULT_SERVER ":1"
#define BUFSIZE 65535

#ifndef INADDR_LOOPBACK
# define INADDR_LOOPBACK ((in_addr_t) 0x7f000001)
#endif

static int verbose = 0;

/* struct pixel - holds one pixel in PPM format */

struct pixel {
	unsigned char red;
	unsigned char green;
	unsigned char blue;
};

/* struct FramebufferFormat - describes the layout of a VNC framebuffer */

struct FramebufferFormat {
	uint16_t width, height;
	int bits_per_pixel, bytes_per_pixel, depth, big_endian, true_color;
	uint16_t red_max, green_max, blue_max;
	int red_bits, green_bits, blue_bits;
	int red_shift, green_shift, blue_shift;
};

/********** struct FramebufferFormat FUNCTIONS **********/

/* decode the network format in 'buf' and store it in 'fbf' */

void decode_PixelFormat (unsigned char *buf,
			 struct FramebufferFormat *fbf)
{
	fbf->bits_per_pixel = buf[0];
	fbf->bytes_per_pixel = fbf->bits_per_pixel / 8;
	fbf->depth = buf[1];
	fbf->big_endian = buf[2];
	fbf->true_color = buf[3];

	memcpy (&fbf->red_max, buf+4, 2);
	memcpy (&fbf->green_max, buf+6, 2);
	memcpy (&fbf->blue_max, buf+8, 2);
	fbf->red_max = ntohs(fbf->red_max);
	fbf->green_max = ntohs(fbf->green_max);
	fbf->blue_max = ntohs(fbf->blue_max);
	for (fbf->red_bits = 1; (1 << fbf->red_bits) < fbf->red_max; )
		fbf->red_bits ++;
	for (fbf->green_bits = 1; (1 << fbf->green_bits) < fbf->green_max; )
		fbf->green_bits ++;
	for (fbf->blue_bits = 1; (1 << fbf->blue_bits) < fbf->blue_max; )
		fbf->blue_bits ++;

	fbf->red_shift=buf[10];
	fbf->green_shift=buf[11];
	fbf->blue_shift=buf[12];
}

void decode_FramebufferFormat (unsigned char *buf,
			       struct FramebufferFormat *fbf)
{
	memcpy (&fbf->width, buf, 2);
	memcpy (&fbf->height, buf+2, 2);
	fbf->width = ntohs(fbf->width);
	fbf->height = ntohs(fbf->height);

	decode_PixelFormat (buf+4, fbf);
}

/* encode the format in 'fbf' into 20-byte, network-ready 'buf' */

void encode_FramebufferFormat (unsigned char *buf,
			       struct FramebufferFormat *fbf)
{
	uint16_t val;

	val = htons(fbf->width);
	memcpy(buf, &val, 2);
	val = htons(fbf->height);
	memcpy(buf+2, &val, 2);

	buf += 4;

	buf[0] = (unsigned char) fbf->bits_per_pixel;
	buf[1] = (unsigned char) fbf->depth;
	buf[2] = (unsigned char) fbf->big_endian;
	buf[3] = (unsigned char) fbf->true_color;

	val = htons(fbf->red_max);
	memcpy(buf+4, &val, 2);
	val = htons(fbf->green_max);
	memcpy(buf+6, &val, 2);
	val = htons(fbf->blue_max);
	memcpy(buf+8, &val, 2);

	buf[10] = (unsigned char) fbf->red_shift;
	buf[11] = (unsigned char) fbf->green_shift;
	buf[12] = (unsigned char) fbf->blue_shift;

	/* three bytes of padding bring us to 15, the four we added earlier
	 * gives 19 (or 20)
	 */
}

void print_FramebufferFormat(FILE *file, struct FramebufferFormat *format)
{
	fprintf(file, "%dx%dx%d %s endian %s RFB session\n",
		format->width, format->height, format->bits_per_pixel,
		format->big_endian ? "big" : "little",
		format->true_color ? "true color" : "colormap");
	fprintf(file, "red %x/%d, green %x/%d, blue %x/%d\n",
		format->red_max, format->red_shift,
		format->green_max, format->green_shift,
		format->blue_max, format->blue_shift);
}

/********** read/write UTILITY FUNCTIONS **********/

/* These functions repeatedly call read(2) or write(2) until the
 * requested number of bytes have been transfered or there's
 * been an error (in which case they exit the program).
 */

static ssize_t do_write (int fd, const void *buf, size_t len)
{
	while (len) {
		ssize_t wrote = write (fd, buf, len);
		if (wrote < 0) {
			perror ("write");
			exit (1);
		}
		buf += wrote;
		len -= wrote;
	}
	return len;
}

static ssize_t do_read (int fd, void *buf, size_t len)
{
	while (len) {
		ssize_t got = read (fd, buf, len);
		if (got < 0) {
			perror ("read");
			exit (1);
		}
		if (!got)
			break;
		buf += got;
		len -= got;
	}
	return len;
}

/********** WRITING FBS FILES **********/

static int write_packet (FILE *f, const void *buf, size_t len,
			 struct timeval *tvp)
{
	uint32_t timestamp = htonl (1000 * tvp->tv_sec + tvp->tv_usec / 1000);
	uint32_t dlen = htonl (len);
	len = 4 * ((len + 3) / 4);
	fwrite (&dlen, 4, 1, f);
	fwrite (buf, 1, len, f);
	fwrite (&timestamp, 4, 1, f);
	return 0;
}

/********** READING FBS FILES **********/

/* These functions are here because we might have RFB messages
 * spanning multiple packets in the FBS file.  So we need to
 * 'automatically' move to the next packet whenever we run out of data
 * in the current one.  Of course, with computers, nothing happens
 * 'automatically'.  Sigh.  We use a 'fileptr' structure to keep trace
 * of where we are in the recorded file.  'next_packet' always points
 * to the next FBS packet in the mmap'ed file; 'buf' points to the
 * current byte in the current packet; 'len' indicates how many
 * bytes are left in the current packet; 'ms' is the timestamp
 * on the current packet.
 */

typedef struct fbs_fileptr {
	unsigned char *map;
	size_t map_size;

	int major_version;
	int minor_version;

	unsigned char *next_packet;
	unsigned char *buf;
	size_t len;
	unsigned long ms;
} FBSfile;

/* next_packet() advances to the next FBS packet in the input steam
 *
 * We really don't have to consider read errors, since we've mmap()'ed
 * the entire FBS file, but if the file is truncated (a common
 * occurance) or we get out sync somehow, we can hit EOF way down deep
 * inside these routines.  This is particularly an issue when we're
 * playing back a series of files and one of them is truncated.
 * We've got to make sure we cleanly end the last FramebufferUpdate,
 * so we keep reading zeros after EOF.  This can produce a bunch
 * of zero-sized rectangles, which generate only warnings with
 * xvncviewer.
 */

static int fbs_at_eof(FBSfile *file) {
	return (file->len == 0);
}

static void next_packet(FBSfile *file) {

	uint32_t *bit32;

	if (file->len == 0) {
		/* past EOF - do nothing */
		return;
	}

	if (file->map + file->map_size - file->next_packet
	    < (2 * sizeof (uint32_t))) {
		/* at EOF - set EOF flag */
		file->len = 0;
		return;
	}

	bit32 = (uint32_t *) file->next_packet;
	file->len = ntohl (*bit32);

	if (file->map + file->map_size - file->next_packet
	    < (2 * sizeof (uint32_t)) + file->len) {
		/* something's wrong with this file - the next packet
		 * appears to go past EOF.  Signal EOF now.
		 */
		file->len = 0;
		return;
	}

	/* delay from start of capture in milliseconds */

	bit32 = (uint32_t *) (4 + file->next_packet
			      + 4 * ((file->len + 3)/ 4));
	file->ms = ntohl (*bit32);

	/* set buf to start of data packet */
	file->buf = file->next_packet + sizeof (uint32_t);

	/* set next_packet to start of next data packet */
	file->next_packet += 2 * sizeof (uint32_t) + 4 * ((file->len + 3) / 4);

	if (verbose >= 3) {
		fprintf(stderr, "next_packet(): offset=%d len=%d ms=%ld\n",
			file->buf - file->map, file->len, file->ms);
	}
}

static void FBSclose(FBSfile *file)
{
	if ((file->map != NULL)  &&  (file->map != MAP_FAILED)) {
		munmap (file->map, file->map_size);
	}
	file->map = NULL;
}

static int FBSopen (const char *filename, FBSfile *fileptr)
{
	int fd;
	struct stat st;

	if ((fd = open (filename, O_RDONLY)) < 0) {
		perror(filename);
		return -1;
	}

	if (fstat (fd, &st) == -1) {
		perror(filename);
		close(fd);
		return -1;
	}

	fileptr->map = mmap (NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	fileptr->map_size = st.st_size;

	if (fileptr->map == MAP_FAILED) {
		perror ("Couldn't map input file");
		close (fd);
		return -1;
	}

	close (fd);

	if (strncmp (fileptr->map, "FBS 001.", 8) != 0) {
		fprintf (stderr, "%s: Incorrect FBS version\n", filename);
		FBSclose(fileptr);
		return -1;
	}

	fileptr->major_version = 1;
	fileptr->minor_version = fileptr->map[10] - '0';

	fileptr->next_packet = fileptr->map + 12; /* Skip version */
	fileptr->len = 12;

	next_packet(fileptr);
	return 0;
}

/* Copy a number of bytes from the mmap'ed data stream, jumping to
 * additional FBS packets if needed.  'dest' can be NULL, which
 * advances the pointer past the bytes without copying them.
 */

void get_bytes(FBSfile *file, void *dest, int bytes)
{
	/* The difference between ">=" and ">" here is quite
	 * pronounced.  Often (but not always), the end of an FBS
	 * packet corresponds to the end of an RFB packet in the
	 * underlying stream.  Often this corresponds to a jump
	 * discontinuity in the timestamps, since if the session is
	 * quiet for a while, there'll be a final RFB packet ending a
	 * final FBS packet, then the next FBS (and RFB) packet will
	 * correspond to the moment when the session starts changing
	 * again.
	 *
	 * Obviously, we've got to handle this case right, or the
	 * last change made to the framebuffer before a pause will
	 * be exported after the pause, or the first change made
	 * after the pause will appear before the pause.
	 *
	 * That's where the ">=" comes in.  When we read exactly to
	 * the end of an FBS packet, we immediately advance to the
	 * next packet (without waiting for the next read).  This
	 * updates our timestamp to the next packet's.  So, if a
	 * framebuffer update ends on a packet boundary, when we're
	 * done processing the update, we will have advanced to the
	 * next packet's timestamp.  This causes a series of frames to
	 * be exported before we begin processing the next packet.
	 */

	while ((bytes >= file->len) && !fbs_at_eof(file)) {
		bytes -= file->len;
		if (dest) {
			memcpy(dest, file->buf, file->len);
			dest += file->len;
		}
		next_packet(file);
	}

	if (bytes > 0) {
		if (fbs_at_eof(file)) {
			if (dest) bzero(dest, bytes);
		} else {
			if (dest) memcpy(dest, file->buf, bytes);
			file->buf += bytes;
			file->len -= bytes;
		}
	}
}

unsigned char get_uchar(FBSfile *file) {
	unsigned char val;
	get_bytes(file, &val, 1);
	return val;
}

uint16_t get_short(FBSfile *file) {
	uint16_t val;
	get_bytes(file, (unsigned char *) &val, 2);
	return ntohs(val);
}

uint32_t get_long(FBSfile *file) {
	uint32_t val;
	get_bytes(file, &val, 4);
	return ntohl(val);
}

/* Read an RFB-format pixel from the input stream in the specified
 * FramebufferFormat, convert it to PPM format and store it in *pptr.
 *
 * This function tacitly assumes that fbf->bytes_per_pixel is <= 4
 * here (i.e, the pixel will fit into a uint32_t)
 */

void get_pixel(FBSfile *file, struct FramebufferFormat *format,
	       struct pixel *pptr) {

	unsigned char buf[4];
	int i;
	uint32_t rawpixel=0, pixel;

	/* Profiling shows this function as a bottleneck, so we go to
	 * a little extra trouble here with the byte ordering.
	 */

	if (format->big_endian) {
#if __BYTE_ORDER == __BIG_ENDIAN
		get_bytes(file, &rawpixel, format->bytes_per_pixel);
#else
		get_bytes(file, buf, format->bytes_per_pixel);
		for (i = 0; i < format->bytes_per_pixel; i++) {
			rawpixel <<= 8;
			rawpixel |= buf[i];
		}
#endif
	} else {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		get_bytes(file, &rawpixel, format->bytes_per_pixel);
#else
		get_bytes(file, buf, format->bytes_per_pixel);
		for (i = 0; i < format->bytes_per_pixel; i++) {
			rawpixel |= buf[i] << (8*i);
		}
#endif
	}

	pixel = rawpixel;
	pixel >>= format->red_shift;
	pixel &= format->red_max;
	pixel <<= (8 - format->red_bits);
	pptr->red = (unsigned char) pixel;

	pixel = rawpixel;
	pixel >>= format->green_shift;
	pixel &= format->green_max;
	pixel <<= (8 - format->green_bits);
	pptr->green = (unsigned char) pixel;

	pixel = rawpixel;
	pixel >>= format->blue_shift;
	pixel &= format->blue_max;
	pixel <<= (8 - format->blue_bits);
	pptr->blue = (unsigned char) pixel;
}

static int get_initial_RFB_handshake(FBSfile *file,
				     struct FramebufferFormat *format)
{
	int minor_protocol_version;
	char buffer[32];
	int auth;
	int length;

	/* The server hello (RFB version 3.x, we hope) */

	get_bytes(file, &buffer, 12);
	if (strncmp(buffer, "RFB 003.", 8) != 0) {
		fprintf(stderr, "Unknown RFB protocol\n");
		return -1;
	}
	minor_protocol_version = buffer[10] - '0';

	if (minor_protocol_version == 3) {

		/* The authentication scheme */

		auth = get_long(file);

		if (auth == 0) {

			/* a real useful session! */
			fprintf(stderr, "session failed authentication!\n");
			return -1;

		} else if (auth == 1) {

			/* No authentication used (or none recorded) */

		} else if (auth == 2) {

			/* first a sixteen byte challenge */
			get_bytes(file, NULL, 16);

			/* we don't see the client response */

			/* now the result of the authentication */
			auth = get_long(file);

			if (auth != 0) {
				/* another real useful session! */
				fprintf(stderr,
					"session failed authentication!\n");
				return -1;
			}

		} else {
			fprintf(stderr,
				"session used unknown authentication!\n");
			return -1;
		}

	} else {

		int num_security_types = get_uchar(file);

		get_bytes(file, NULL, num_security_types);

		/* Now we've got a problem.  In version 3.7 (and newer),
		 * the client now picks on of the security types for
		 * authentication.  But since we only record server
		 * messages, there's no way to know which one got picked.
		 * Sigh.  We assume that the record code discarded
		 * all the authentication details and proceed...
		 */
	}

	/* ServerInitialisation */

	get_bytes(file, &buffer, 20);
	decode_FramebufferFormat(buffer, format);

	if (verbose > 0) {
		fprintf(stderr, "file uses format:\n");
		print_FramebufferFormat(stderr, format);
	}

	/* name of desktop */

	length = get_long(file);
	get_bytes(file, NULL, length);

	return 0;
}

/********** BUFFERED OUTPUT **********/

int fput_short(uint16_t val, FILE *file)
{
	val = htons(val);
	return fwrite(&val, 2, 1, file);
}

int fput_long(uint32_t val, FILE *file)
{
	val = htonl(val);
	return fwrite(&val, 4, 1, file);
}

/* just like get_pixel, we assume the pixel will fit into 32 bits */

int fput_pixel(struct pixel *pptr, struct FramebufferFormat *format,
	       FILE *file)
{
	uint32_t pixel;
	int ret;

	pixel = ((pptr->red >> (8 - format->red_bits))
		 << format->red_shift)
		| ((pptr->green >> (8 - format->green_bits))
		   << format->green_shift)
		| ((pptr->blue >> (8 - format->blue_bits))
		   << format->blue_shift);

	if (format->big_endian) {
		switch (format->bytes_per_pixel) {
		case 4:
			fputc(pixel>>24, file);
		case 3:
			fputc((pixel>>16) & 0xff, file);
		case 2:
			fputc((pixel>>8) & 0xff, file);
		case 1:
		default:
			return fputc(pixel & 0xff, file);
		}
	} else {
		ret = fputc(pixel & 0xff, file);
		if (format->bytes_per_pixel >= 2)
			ret = fputc((pixel>>8) & 0xff, file);
		if (format->bytes_per_pixel >= 3)
			ret = fputc((pixel>>16) & 0xff, file);
		if (format->bytes_per_pixel == 4)
			ret =  fputc(pixel>>24, file);
		return ret;
	}
}

/********** VARIOUS AUTHENTICATION SCHEMES **********/

/* Passthrough authentication is when we have a client connecting
 * through this program to a server.  We let them authenticate with
 * each other and just record the key information about the session.
 * This can get tricky as we do need to track the authentication as it
 * happens, and have no direct control over which protocol version is
 * used.  We support RFB protocol versions 3.3, 3.7, and 3.8.
 *
 * The FBS log file is 'f' and the server's default format is written
 * to 'fbf'
 */

static int do_passthrough_authentication (int server, int clientr, int clientw,
					  FILE *f, int do_events_instead,
					  struct FramebufferFormat *fbf)
{
	char packet[24];
	size_t packet_size;
	struct timeval start;
	uint32_t auth;
	int protocol_minor_version;

	start.tv_sec = 0;
	start.tv_usec = 0;

	/* ProtocolVersion */
	if (do_read (server, packet, 12)) {
		fprintf(stderr, "Can't read server ProtocolVersion\n");
		return 1;
	}
	do_write (clientw, packet, 12);
	if (do_read (clientr, packet, 12)) {
		fprintf(stderr, "Can't read client ProtocolVersion\n");
		return 1;
	}
	do_write (server, packet, 12);
	if (!do_events_instead)
		/* Record the protocol in use */
		write_packet (f, packet, 12, &start);
	packet_size = 4;
	protocol_minor_version = packet[10] - '0';
	if (protocol_minor_version >= 7) {
		packet_size = 1;
	}

	/* Authentication */
	if (do_read (server, packet, packet_size)) {
		fprintf(stderr, "Can't read server authentication start\n");
		return 1;
	}

	if (protocol_minor_version == 3) {
		uint32_t noauth = htonl (1);
		do_write (clientw, packet, 4);
		memcpy (&auth, packet, 4);
		auth = ntohl (auth);
		if (!do_events_instead) {
			memcpy (packet, &noauth, 4);
			write_packet (f, packet, 4, &start);
		}
	} else {
		size_t num_types;
		num_types = (size_t) packet[0];
		if (num_types == 0) {
			uint32_t reason_length;
			if (do_read (server, &reason_length, 4)) {
				fprintf(stderr,
					"Can't read server reason length\n");
				return 1;
			}
			reason_length = ntohl(reason_length);
			if (do_read (server, packet, reason_length)) {
				fprintf(stderr, "Can't read server reason\n");
				return 1;
			}
			fprintf(stderr, "Connection failed: %.*s\n",
				(int) reason_length, packet);
			return 1;
		}
		if (do_read (server, packet + 1, num_types)) {
			fprintf(stderr, "Can't read server auth type list\n");
			return 1;
		}
		do_write (clientw, packet, num_types + 1);
		if (do_read (clientr, packet, 1)) {
			fprintf(stderr, "Can't read client auth type\n");
			return 1;
		}
		do_write (server, packet, 1);
		auth = (uint32_t) packet[0];
		if (!do_events_instead) {
			packet[0] = 1;
			packet[1] = 1;
			write_packet (f, packet, 2, &start);
		}
	}

	/* auth type 0 (authentication failed) can be ignored,
	 * and auth type 1 (no authentication) just skips ahead
	 * in pre-3.8 protocol versions.
	 */

	if ((auth == 1) && (protocol_minor_version >= 8)) {
		if (do_read (server, packet, 4)) {
			fprintf(stderr, "Can't read server auth response\n");
			return 1;
		}
		do_write (clientw, packet, 4);
	}

	if (auth == 2) {
		/* Don't record this stuff. */
		if (do_read (server, packet, 16)) {
			fprintf(stderr, "Can't read server challenge\n");
			return 1;
		}
		do_write (clientw, packet, 16);
		if (do_read (clientr, packet, 16)) {
			fprintf(stderr, "Can't read client response\n");
			return 1;
		}
		do_write (server, packet, 16);
		if (do_read (server, packet, 4)) {
			fprintf(stderr, "Can't read server auth response\n");
			return 1;
		}
		do_write (clientw, packet, 4);
	}

	if (auth > 2) {
		fprintf(stderr, "Authentication type %d not understood\n",
			auth);
	}

	/* ClientInitialisation */
	if (do_read (clientr, packet, 1)) {
		fprintf(stderr, "Can't read client shared-session flag\n");
		return 1;
	}
	do_write (server, packet, 1);

	/* ServerInitialisation */
	if (do_read (server, packet, 24)) {
		fprintf(stderr, "Can't read ServerInitialization\n");
		return 1;
	} else {
		uint32_t name_length;
		char *buffer;

		if (fbf != NULL) {
			decode_FramebufferFormat(packet, fbf);
		}

		memcpy (&name_length, packet + 20, 4);
		name_length = ntohl (name_length);
		buffer = malloc (name_length);
		if (!buffer) {
			fprintf(stderr, "Can't malloc desktop name\n");
			return 1;
		}
		if (do_read (server, buffer, name_length)) {
			fprintf(stderr, "Can't read server desktop name\n");
			free (buffer);
			return 1;
		}
		do_write (clientw, packet, 24);
		do_write (clientw, buffer, name_length);
		if (!do_events_instead) {
			write_packet (f, packet, 24, &start);
			if (name_length > 0) {
				write_packet (f, buffer, name_length, &start);
			}
		}
		free (buffer);
	}

	return 0;
}

/* Standalone authentication occurs when we don't have a client to 'help'
 * us authenticate to a server.  We do VNC 3.3 authentication ourselves.
 *
 * The FBS log file is 'f' and the server's default format is written to 'fbf'
 */

static int do_standalone_authentication (int server, FILE *f,
					 struct FramebufferFormat * fbf, char * vnc_password)
{
	char packet[24];
	size_t packet_size;
	struct timeval start;
	uint32_t auth;
	uint32_t noauth = htonl (1);

	start.tv_sec = 0;
	start.tv_usec = 0;

	/* ProtocolVersion */
	if (do_read (server, packet, 12))
		return 1;

	/* If the server announced a version higher than 3.3, then
	 * we'll downgrade to 3.3.  Make sure the file version
	 * reflects this - otherwise it will look like a higher
	 * version than it is.
	 */
	if ((packet[6] > '3') || (packet[10] > '3')) {
		packet[6] = '3';
		packet[10] = '3';
	}
	write_packet (f, packet, 12, &start);

	do_write (server, "RFB 003.003\n", 12);

	/* Authentication */
	packet_size = 4;
	if (do_read (server, packet, packet_size))
		return 1;

	memcpy (&auth, packet, 4);
	auth = ntohl (auth);
	/* we record a 'noauth' packet in the trace file
	 * because we don't want to record the authentication
	 */
	memcpy (packet, &noauth, 4);
	write_packet (f, packet, 4, &start);

	if (auth != 1) {
		char *passwd;
		char challenge[16];
		int i;
		uint32_t authResult;

		if (do_read (server, challenge, sizeof(challenge)))
			return 1;

        if (vnc_password) {
            passwd = vnc_password;
        } else {
            passwd = getpass("Password: ");
        }

		if ((!passwd) || (strlen(passwd) == 0)) {
			fprintf(stderr,"Reading password failed\n");
			return 1;
		}

		if (strlen(passwd) > 8) {
			passwd[8] = '\0';
		}

		vncEncryptBytes(challenge, passwd);

		/* Lose the password from memory */
		for (i = strlen(passwd); i >= 0; i--) {
			passwd[i] = '\0';
		}

		do_write (server, challenge, sizeof(challenge));

		packet_size = 4;
		if (do_read (server, packet, packet_size))
			return 1;

		memcpy (&authResult, packet, 4);
		authResult = ntohl(authResult);

		switch (authResult) {
		case 0:
			fprintf(stderr,"VNC authentication succeeded\n");
			break;
		case 1:
			fprintf(stderr,"VNC authentication failed -"
				"bad password\n");
			return 1;
		case 2:
			fprintf(stderr,"VNC authentication failed - "
				"too many tries\n");
			return 1;
		default:
			fprintf(stderr,"Unknown VNC authentication result: %d\n",
				(int)authResult);
			return 1;
		}
	}

	/* ClientInitialisation - ask for a shared session */
	do_write (server, "s", 1);

	/* ServerInitialisation */
	if (do_read (server, packet, 24))
		return 1;
	else {
		uint32_t name_length;
		char *buffer;

		if (fbf != NULL) {
			decode_FramebufferFormat(packet, fbf);
		}

		memcpy (&name_length, packet + 20, 4);
		name_length = ntohl (name_length);
		buffer = malloc (name_length);
		if (!buffer)
			return 1;
		if (do_read (server, buffer, name_length)) {
			free (buffer);
			return 1;
		}
		write_packet (f, packet, 24, &start);
		if (name_length > 0) {
			write_packet (f, buffer, name_length, &start);
		}
		free (buffer);
	}

	return 0;
}

/* This is used when a client is connecting to us as the server.
 * We use VNC 3.3.
 *
 * 'fbf' needs to be initialized before this function is called; it's
 * the default server format this function announces to the client.
 */

static int do_server_initialization (int clientr, int clientw,
				     struct FramebufferFormat *fbf)
{
	char packet[24];
	uint32_t noauth = htonl(1);

	/* s->c ProtocolVersion */
	do_write (clientw, "RFB 003.003\n", 12);

	/* c->s ProtocolVersion */
	if (do_read (clientr, packet, 12))
		return 1;

	/* s->c no authentication */
	do_write (clientw, &noauth, 4);

	/* c->s client initialization - shared flag - ignored  */
	if (do_read (clientr, packet, 1))
		return 1;

	/* s->c server initialization - 20 bytes of format plus four byte
	 * integer indicating a zero length name string
	 */
	bzero(packet, 24);
	encode_FramebufferFormat(packet, fbf);
	do_write (clientw, packet, 24);

	return 0;
}

/********** RECORDING **********/

/* RFB client messages can be regarded as having two parts - a
 * constant-sized part followed by a variable-sized part.  The size of
 * the variable part depends only on the constant part.  This function
 * returns the size of a variable part, given a pointer to a constant
 * part.
 */

static size_t variable_part (char *buffer)
{
	int message = (int) *buffer;
	switch (message) {
	case 0: /* SetPixelFormat */
	case 3: /* FramebufferUpdateRequest */
	case 4: /* KeyEvent */
	case 5: /* PointerEvent */
		/* No variable part */
		return 0;
	case 1: /* FixColourMapEntries */
	{
		uint16_t number_of_colours;
		memcpy (&number_of_colours, buffer + 4, 2);
		number_of_colours = ntohs (number_of_colours);
		return number_of_colours * 6;
	}
	case 2: /* SetEncodings */
	{
		uint16_t number_of_encodings;
		memcpy (&number_of_encodings, buffer + 2, 2);
		number_of_encodings = ntohs (number_of_encodings);
		return number_of_encodings * 4;
	}
	case 6: /* ClientCutText */
	{
		uint32_t length;
		memcpy (&length, buffer + 4, 4);
		length = ntohl (length);
		return length;
	}
	} /* switch */

	/* Caught earlier anwyay */
	fprintf (stderr, "Protocol error\n");
	exit (1);
}

/* For recording */
static int process_client_message (char *fixed, char *variable, FILE *f)
{
	static int first = 1;
	static char delayed_output[100];
	static int elapsed;
	static struct timeval last_tv, first_tv;
	struct timeval tv, diff;
	struct timezone tz;
	static unsigned int last_was_key_down;
	static unsigned int current_x, current_y;
	static unsigned char current_buttons;
	int ms;
	int message = (int) *fixed;

	gettimeofday (&tv, &tz);
	if (!last_tv.tv_sec && !last_tv.tv_usec)
		first_tv = last_tv = tv;
	diff.tv_sec = tv.tv_sec - last_tv.tv_sec;
	diff.tv_usec = tv.tv_usec - last_tv.tv_usec;
	ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;

	if (first) {
		first = 0;
		fputs ("RFM 001.000\nshared\n", f);
	} else if (*delayed_output && (!last_was_key_down || message > 4)) {
		/* We need to output a deferred line after calculating
		 * the delay */
		if (ms > 0) {
			char *p = delayed_output + strlen (delayed_output);
			sprintf (p, " delay %dms", ms);
		}
		strcat (delayed_output, "\n");
		fputs (delayed_output, f);
		last_tv = tv;
		*delayed_output = '\0';
	}

	switch (message) {
	case 0: /* SetPixelFormat */
	case 1: /* FixColourMapEntries */
	case 2: /* SetEncodings */
	case 3: /* FramebufferUpdateRequest */
		diff.tv_sec = tv.tv_sec - first_tv.tv_sec;
		diff.tv_usec = tv.tv_usec - first_tv.tv_usec;
		ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;
		if (ms > (1000 * (1 + elapsed))) {
			fprintf (f, "# At %dms from start\n", ms);
			elapsed = ms / 1000;
		}
		return 0;
	case 4: /* KeyEvent */
	{
		char *p = delayed_output;
		const char *down_flag = "up";
		uint32_t key;

		memcpy (&key, fixed + 4, 4);
		key = ntohl (key);

		/* We might be changing key up/down into press */
		if (*delayed_output) {
			/* last_was_key_down is the last key down */
			if (fixed[1] || last_was_key_down != key || ms > 400) {
				/* Can't make a press out of that */
				char *p = delayed_output;
				p += strlen (p);
				if (ms > 0)
					sprintf (p, " delay %dms", ms);
				strcat (delayed_output, "\n");
				fputs (delayed_output, f);
				last_tv = tv;
				*delayed_output = '\0';
				last_was_key_down = 0;
			} else {
				char *p = delayed_output;
				char *end;
				p += strcspn (p, " \t");
				p += strspn (p, " \t");
				end = p + strcspn (p, " \t");
				*end = '\0';
				end = strdup (p);
				sprintf (delayed_output, "press %s", end);
				last_was_key_down = 0;
				break;
			}
		}

		if (fixed[1]) {
			last_was_key_down = key;
			down_flag = "down";
		}
		sprintf (p, "key ");
		p += strlen (p);
		if (key < 256 && isprint ((char) key) && !isspace ((char) key))
			*p++ = (char) key;
		else {
			sprintf (p, "%#x", key);
			p += strlen (p);
		}

		sprintf (p, " %s", down_flag);
		break;
	}
	case 5: /* PointerEvent */
	{
		uint16_t x, y;
		unsigned char buttons = fixed[1];
		memcpy (&x, fixed + 2, 2);
		memcpy (&y, fixed + 4, 2);
		x = ntohs (x);
		y = ntohs (y);

		/* First deal with buttons */
		if (buttons != current_buttons) {
			int i;
			int diff = buttons ^ current_buttons;
			while ((i = ffs (diff))) {
				if (*delayed_output) {
					strcat (delayed_output, "\n");
					fputs (delayed_output, f);
				}
				i--;
				sprintf (delayed_output,
					 "button %d %s", i,
					 (buttons & (1<<i)) ? "down" : "up");
				diff ^= 1<<i;
			}
			current_buttons = buttons;
		}

		/* Now deal with position */
		if (current_x != x || current_y != y) {
			if (*delayed_output) {
				strcat (delayed_output, "\n");
				fputs (delayed_output, f);
			}
			sprintf (delayed_output,
				 "pointer %d %d", x, y);
			current_x = x;
			current_y = y;
		}
		break;
	}
	case 6: /* ClientCutText */
		fputs ("# ClientCutText not supported yet\n", f);
		break;
	default:
		fprintf (stderr, "Protocol error\n");
		exit (1);
	}
	return 0;
}

/* At the end of a shared-session record we'll probably be terminated
 * by a signal (a proxy record will probably be terminated by a client
 * disconnect).  We'll want to write a trailing packet and neatly
 * flush our buffers, so arrange for the first signal (i.e, CNTL-C) to
 * just set a flag.  A second CNTL-C will terminate the program.
 */

int terminating=0;

void signal_handler(int signum)
{
	if (!terminating) {
		terminating = 1;
	} else {
		exit(0);
	}
}

static int record (const char *file, int clientr, int clientw,
		   struct sockaddr_in server_addr, int do_events_instead,
		   int appenddate, int shared_session, char *vnc_password,
		   char *recording_lock_file)
{
	const char *version0 = "FBS 001.000\n";
	const char *version1 = "FBS 001.001\n";
	FILE *f;
	int server = -1;
	struct timeval epoch;
	struct timeval tv;
	struct timeval diff;
	struct timezone tz;
	int first = 1;
	char *buf = malloc (BUFSIZE);
	unsigned char FramebufferUpdateRequest[10];
	struct FramebufferFormat fbf;
	time_t now;	

	if (!buf) {
		fprintf (stderr, "Couldn't allocate buffer\n");
		exit (1);
	}

	if (appenddate)
	{ /* if we're appending the date, make the new filename in 'buf'.  if we're not, just call
	     fopen directly on 'file' */
		if (strlen(file)+17 > BUFSIZE)
		{	/* Ya, like this is going to happen.  whatever */
			fprintf (stderr, "Filename is bigger than filename buffer size.  Increase BUFSIZE and recompile\n");
			exit (1);
		}
		time(&now);
		strftime(buf+sprintf(buf, "%s-", file), 16, "%Y%m%d-%H%M%S", localtime(&now));
		f = fopen (buf, "wb");
	} else {
		f = fopen (file, "wb");
	}
	if (!f) {
		perror ("fopen");
		exit (1);
	}

	if (recording_lock_file) {
        FILE * fre;
		fre = fopen (recording_lock_file, "wb");
		fprintf(fre, "%d", getpid());
		fclose(fre);
	}

	if (!do_events_instead) {
		if (shared_session) {
			fwrite (version1, 1, 12, f);
		} else {
			fwrite (version0, 1, 12, f);
		}
	}

	server = socket (PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (server == -1) {
		perror ("socket");
		goto out;
	}

	if (connect (server, (struct sockaddr *) &server_addr,
		     sizeof (struct sockaddr_in))) {
		perror ("connect");
		goto out;
	}

	if (!shared_session) {
		if (do_passthrough_authentication (server, clientr, clientw,
						   f, do_events_instead, &fbf)) {
			fprintf (stderr, "Error during authentication\n");
			exit (1);
		}
	} else {
		if (do_standalone_authentication (server, f, &fbf, vnc_password)) {
			fprintf (stderr, "Error during authentication\n");
			exit (1);
		}
	}

	/* For a shared session, we now tell the server which pixel
	 * encodings we support.  For a non-shared (i.e, passthrough)
	 * session, we just use whatever our client requests.  This is
	 * different from the pixel format - we can tell from the
	 * framebuffer update which pixel encodings are actually used.
	 * Codings are listed in order of preference.  The ones
	 * our export and translate code currently understand are:
	 *
	 * 5 - hextile
	 * 4 - CoRRE
	 * 2 - RRE
	 * 1 - copyrect
	 * 0 - raw
	 */

	if (shared_session) {
		int codings[] = {5, 4, 2, 1, 0};
		int ncodings = sizeof(codings)/sizeof(int);
		uint16_t nncodings;
		int i;
		unsigned char SetEncodings[32];

		memset(SetEncodings, 0, sizeof(SetEncodings));
		SetEncodings[0] = 2;
		nncodings = htons(ncodings);
		memcpy(SetEncodings+2, &nncodings, 2);
		for (i=0; i<ncodings; i++) {
			uint32_t coding = htonl(codings[i]);
			memcpy(SetEncodings+4*(i+1), &coding, 4);
		}

		do_write (server, SetEncodings, 4*(ncodings+1));
	}

	/* We need to 'prime' a shared session by requesting a copy of
	 * the screen, then constantly re-requesting it.  Construct
	 * an incremental FramebufferUpdateRequest for this purpose.
	 */

	if (shared_session) {
		uint16_t val;
		memset(FramebufferUpdateRequest, 0, 10);
		FramebufferUpdateRequest[0] = 3;
		FramebufferUpdateRequest[1] = 1;
		val = htons(fbf.width);
		memcpy(FramebufferUpdateRequest+6, &val, 2);
		val = htons(fbf.height);
		memcpy(FramebufferUpdateRequest+8, &val, 2);

		do_write (server, FramebufferUpdateRequest, 10);
	}

	fprintf(stderr, "rfbproxy: recording session to %s\n",
		appenddate ? buf : file);

	/* Arrange for clean termination - especially for a shared session */

	signal(SIGINT, signal_handler);		/* CNTL-C */
	signal(SIGTERM, signal_handler);	/* kill's default signal */

	while (1) {
		ssize_t bufs;
		fd_set rfds;
		FD_ZERO (&rfds);
		FD_SET (server, &rfds);
		if (!shared_session) FD_SET (clientr, &rfds);

		if (terminating == 1) {
			shutdown(server, SHUT_WR);
			terminating = 2;
		}

		if ((select(FD_SETSIZE, &rfds, NULL, NULL, NULL) < 0)
		    && errno != EINTR) {
			perror ("select");
			goto out;
		}

		if (FD_ISSET (server, &rfds)) {

			gettimeofday (&tv, &tz);
			if (first) {
				first = 0;
				epoch = tv;
			}
			bufs = read (server, buf, BUFSIZE);
			if (!bufs) break;
			if (!shared_session) do_write (clientw, buf, bufs);
			diff.tv_sec = tv.tv_sec - epoch.tv_sec;
			diff.tv_usec = tv.tv_usec - epoch.tv_usec;
			if (!do_events_instead)
				write_packet (f, buf, bufs, &diff);
			if (shared_session && !terminating)
				do_write(server, FramebufferUpdateRequest, 10);
		}

		if (!shared_session && FD_ISSET(clientr, &rfds)) {
			/* We want to actually listen to the
			 * individual client messages.
			 *
			 * The largest non-variable part of a
			 * client->server message is 20 bytes.  */
			static char tmp_buffer[20];
			static char client_buffer[20];
			static char *variable_buffer;
			static size_t variable_bytes_left;
			static size_t variable_bytes_got;
			static size_t client_bytes_got;
			static size_t client_bytes_left;
			static const size_t mlen[] = {
				20, 6, 4, 10, 8, 6, 8
			}; /* message lengths */
			char *at = tmp_buffer;

			/* Read the available data */
			bufs = read (clientr, tmp_buffer, 20);
			if (!bufs) break;
			if (!terminating) do_write (server, tmp_buffer, bufs);

			if (!do_events_instead)
				continue;

			while (bufs) {
				size_t length;

				/* Figure out where to put it  */
				if (variable_bytes_left) {
					size_t need = bufs;
					if (variable_bytes_left < need)
						need = variable_bytes_left;
					memcpy (variable_buffer +
						variable_bytes_got,
						at, need);
					variable_bytes_got += need;
					variable_bytes_left -= need;
					at += need;
					bufs -= need;
				} else if (client_bytes_left) {
					size_t need = bufs;
					if (client_bytes_left < need)
						need = client_bytes_left;
					memcpy (client_buffer +
						client_bytes_got,
						at, need);
					client_bytes_got += need;
					client_bytes_left -= need;
					at += need;
					bufs -= need;
				} else {
					/* Clean slate */
					*client_buffer = *at++;
					bufs--;
					client_bytes_got = 1;
				}

				/* Figure out what to do with it */
				if (client_buffer[0] > 6) {
					fprintf (stderr,
						 "Protocol error\n");
					exit (1);
				}
				length = mlen[(int) client_buffer[0]];
				if (client_bytes_got < length) {
					client_bytes_left = (length -
							     client_bytes_got);
					/* Incomplete fixed part */
					continue;
				}

				length = variable_part (client_buffer);
				if (variable_bytes_got < length) {
					int need_alloc = !variable_bytes_left;
					variable_bytes_left = length -
						variable_bytes_got;
					if (need_alloc)
						variable_buffer = malloc
							(variable_bytes_left);
					/* Incomplete variable part */
					continue;
				}

				process_client_message (client_buffer,
							variable_buffer, f);
				if (variable_bytes_got) {
					variable_bytes_got = 0;
					free (variable_buffer);
				}
				client_bytes_got = 0;
			}
		}
	}

	/* The last thing we write to the file is a zero length packet
	 * to signal EOF.  It's here to make sure we've got a
	 * timestamped event at the end of the file.
	 */

	if (!do_events_instead) {

		gettimeofday (&tv, &tz);
		diff.tv_sec = tv.tv_sec - epoch.tv_sec;
		diff.tv_usec = tv.tv_usec - epoch.tv_usec;

		write_packet (f, &diff, 0, &diff);
	}


 out:
	free (buf);
	if (server != -1)
		close (server);

	if (fclose (f))
		perror ("Error writing file");

	if (recording_lock_file) {
        unlink(recording_lock_file);
	}
	return 0;
}

/********** PLAYBACK **********/

/* Returns bitmask:
 *
 * bit 0: cycle
 * bit 1: pause
 * bit 2: client did a SetFormat (and it was decoded into 'fbf')
 * bit 3: client did a RequestFramebufferUpdate
 */
static int handle_client_during_playback (int clientr, int cycle, int pause,
					  struct FramebufferFormat *fbf)
{
	/* We want to actually listen to the
	 * individual client messages.
	 *
	 * The largest non-variable part of a
	 * client->server message is 20 bytes.  */
	static char tmp_buffer[20];
	static char client_buffer[20];
	static char *variable_buffer;
	static size_t variable_bytes_left;
	static size_t variable_bytes_got;
	static size_t client_bytes_got;
	static size_t client_bytes_left;
	static const size_t mlen[] = {
		20, 6, 4, 10, 8, 6, 8
	}; /* message lengths */
	char *at = tmp_buffer;
	ssize_t bufs;
	int do_pause = 0;
	int do_cycle = 0;
	int do_setformat = 0;
	int do_updaterequest = 0;

	/* Read the available data */
	bufs = read (clientr, tmp_buffer, 20);
	if (bufs < 1)
		return -1;

	while (bufs) {
		size_t length;

		/* Figure out where to put it  */
		if (variable_bytes_left) {
			size_t need = bufs;
			if (variable_bytes_left < need)
				need = variable_bytes_left;
			memcpy (variable_buffer +
				variable_bytes_got,
				at, need);
			variable_bytes_got += need;
			variable_bytes_left -= need;
			at += need;
			bufs -= need;
		} else if (client_bytes_left) {
			size_t need = bufs;
			if (client_bytes_left < need)
				need = client_bytes_left;
			memcpy (client_buffer +
				client_bytes_got,
				at, need);
			client_bytes_got += need;
			client_bytes_left -= need;
			at += need;
			bufs -= need;
		} else {
			/* Clean slate */
			*client_buffer = *at++;
			bufs--;
			client_bytes_got = 1;
		}

		/* Figure out what to do with it */
		if (client_buffer[0] > 6) {
			fprintf (stderr,
				 "Protocol error (%d)\n", client_buffer[0]);
			exit (1);
		}
		length = mlen[(int) client_buffer[0]];
		if (client_bytes_got < length) {
			client_bytes_left = (length -
					     client_bytes_got);
			/* Incomplete fixed part */
			continue;
		}

		length = variable_part (client_buffer);
		if (variable_bytes_got < length) {
			int need_alloc = !variable_bytes_left;
			variable_bytes_left = length -
				variable_bytes_got;
			if (need_alloc)
				variable_buffer = malloc
					(variable_bytes_left);
			/* Incomplete variable part */
			continue;
		}
		
		if (client_buffer[0] == 0) {
			/* SetPixelFormat */
			decode_PixelFormat(client_buffer + 4, fbf);
			if (verbose > 0) {
				fprintf(stderr, "client SetPixelFormat:\n");
				print_FramebufferFormat(stderr, fbf);
			}
			do_setformat = 4;
		}

		if (client_buffer[0] == 3) {
			/* FramebufferUpdateRequest */
			if (verbose > 2) {
				fprintf(stderr, "FramebufferUpdateRequest\n");
			}
			do_updaterequest = 8;
		}

		if (client_buffer[0] == 4 /* KeyEvent */ &&
		    client_buffer[1] /* Key down */) {
			uint32_t key;
			memcpy (&key, client_buffer + 4, 4);
			key = ntohl (key);
			if (key == pause)
				do_pause = 2 - do_pause;
			if (key == cycle)
				do_cycle = 1;
		}

		if (variable_bytes_got) {
			variable_bytes_got = 0;
			free (variable_buffer);
		}
		client_bytes_got = 0;
	}

	return do_updaterequest | do_setformat | do_pause | do_cycle;
}

/* translate_FramebufferUpdate - translate a single FramebufferUpdate
 * message that starts at the point 'infile' is pointing to and is
 * encoded using 'informat', and write to it 'outfile' using 'outformat'.
 */

/* hextile encoding is complex enough to get its own function */

static void translate_hextile(FBSfile *infile,
			      struct FramebufferFormat *informat,
			      FILE *outfile,
			      struct FramebufferFormat *outformat,
			      int rectx, int recty, int rectw, int recth) {

	int subx, suby;
	int subencoding;
	int subrects, subrect;
	int x, y, xy, wh;
	struct pixel pix, background, foreground;

	for (suby=0; suby<recth; suby+=16) {
		for (subx=0; subx<rectw; subx+=16) {
			fputc(subencoding = get_uchar(infile), outfile);
			if (subencoding & 1) {
				for (y = recty + suby;
				     (y < recty + suby + 16)
					     && (y < recty + recth); y++) {
					for (x = rectx + subx;
					     (x < rectx + subx + 16)
						     && (x < rectx + rectw);
					     x++) {
						get_pixel(infile, informat,
							  &pix);
						fput_pixel(&pix, outformat,
							   outfile);
					}
				}
			} else {
				if (subencoding & 2) {
					get_pixel(infile, informat,
						  &background);
					fput_pixel(&background, outformat,
						   outfile);
				}
				if (subencoding & 4) {
					get_pixel(infile, informat,
						  &foreground);
					fput_pixel(&foreground, outformat,
						   outfile);
				}
				if (subencoding & 8) {
					fputc(subrects = get_uchar(infile),
					      outfile);
					for (subrect = 0; subrect < subrects;
					     subrect ++) {
						if (subencoding & 16) {
							get_pixel(infile,
								  informat,
								  &pix);
							fput_pixel(&pix,
								   outformat,
								   outfile);
						}
						fputc(xy = get_uchar(infile),
						      outfile);
						fputc(wh = get_uchar(infile),
						      outfile);
					}
				}
			}
		}
	}
}

static void translate_FramebufferUpdate(FBSfile *infile, FILE *outfile,
					struct FramebufferFormat *informat,
					struct FramebufferFormat *outformat)
{
	int rect, subrect, x, y;
	int srcx, srcy;
	uint16_t nrects;
	uint16_t rectx, recty, rectw, recth;
	uint32_t type;
	uint32_t nsubrects;
	uint16_t subx, suby, subw, subh;
	struct pixel pix;

	fput_short(get_short(infile), outfile);
	fput_short(nrects = get_short(infile), outfile);

	if (verbose > 2)
		fprintf(stderr, "Framebuffer update (%d rects)\n", nrects);

	for (rect = 0; rect < nrects; rect ++) {

		fput_short(rectx = get_short(infile), outfile);
		fput_short(recty = get_short(infile), outfile);
		fput_short(rectw = get_short(infile), outfile);
		fput_short(recth = get_short(infile), outfile);
		fput_long(type = get_long(infile), outfile);

		if (verbose > 3)
			fprintf(stderr, "rect %d: (%d,%d) %dx%d type %d\n",
				rect, rectx, recty, rectw, recth, type);

		switch (type) {
		case 0:
			/* raw */
			for (y = recty; y < recty+recth; y++) {
				for (x = rectx; x < rectx+rectw; x++) {
					get_pixel(infile, informat, &pix);
					fput_pixel(&pix, outformat, outfile);
				}
			}
			break;

		case 1:
			/* copy rect */
			fput_short(srcx = get_short(infile), outfile);
			fput_short(srcy = get_short(infile), outfile);
			break;

		case 2:
			/* RRE */
			fput_long(nsubrects = get_long(infile), outfile);
			get_pixel(infile, informat, &pix);
			fput_pixel(&pix, outformat, outfile);

			for (subrect=0; subrect<nsubrects; subrect++) {
				get_pixel(infile, informat, &pix);
				fput_pixel(&pix, outformat, outfile);
				fput_short(subx = get_short(infile), outfile);
				fput_short(suby = get_short(infile), outfile);
				fput_short(subw = get_short(infile), outfile);
				fput_short(subh = get_short(infile), outfile);
			}
			break;

		case 4:
			/* CoRRE */
			fput_long(nsubrects = get_long(infile), outfile);
			get_pixel(infile, informat, &pix);
			fput_pixel(&pix, outformat, outfile);

			for (subrect=0; subrect<nsubrects; subrect++) {
				get_pixel(infile, informat, &pix);
				fput_pixel(&pix, outformat, outfile);
				fputc(subx = get_uchar(infile), outfile);
				fputc(suby = get_uchar(infile), outfile);
				fputc(subw = get_uchar(infile), outfile);
				fputc(subh = get_uchar(infile), outfile);
			}
			break;

		case 5:
			translate_hextile (infile, informat,
					   outfile, outformat,
					   rectx, recty, rectw, recth);
			break;

		default:

			/* We don't understand the pixel encoding.
			 * Maybe we should just bail here, but try to
			 * keep going.  Skip to next packet, and do an
			 * immediate return to halt processing of this
			 * FramebufferUpdate.
			 */

			fprintf(stderr, "Unknown pixel encoding (%d)\n", type);
			next_packet(infile);
			return;

		}
	}
}

static int playback (const char *filename, int clientr, int clientw, int loop,
		     int cycle, int pause)
{
	FBSfile fileptr;
	struct FramebufferFormat server_fbf;
	FILE *outfile;

	unsigned long last_packet_ms;
	int ret = -1;
	int paused = 0;
	int finish = 0;

	/* These next two are static because they need to be preserved
	 * over repeated calls to this function during a looping and/or
	 * multi-file playback: the client framebuffer format and a flag
	 * to keep FramebufferUpdatesRequests and FramebufferUpdates
	 * syncronized during FBS 1.1 playbacks.
	 *
	 * 'can_update' is cleared ever time we send a FramebufferUpdate,
	 * is set every time the client sends a FramebufferUpdateRequest,
	 * and we won't send a FramebufferUpdate unless it is set.
	 * The net net is that after sending an update, we wait to hear
	 * a request back from the client before sending more updates.
	 * This is done for two reasons:
	 *
	 *   1) we can (FBS 1.0 playback can't do this because we can't
	 *      find its message boundaries), and
	 *   2) we don't want to be in the middle of sending a update
	 *      when the client changes pixel formats on us!
	 */

	static struct FramebufferFormat client_fbf;
	static int can_update = 0;

	if (FBSopen(filename, &fileptr) == -1) {
		return -1;
	}

	if (get_initial_RFB_handshake(&fileptr, &server_fbf) == -1) {
		FBSclose(&fileptr);
		return -1;
	}

	if (!loop) {
		do_server_initialization(clientr, clientw, &server_fbf);
		client_fbf = server_fbf;
	}

	/* the dup() is done so we can fclose() at the end of this function */

	if ((clientw = dup(clientw)) == -1) {
		perror("dup");
		FBSclose(&fileptr);
		return -1;
	}
	outfile = fdopen(clientw, "w");

	/* now this is the timestamp on the first thing _following_
         * server init
	 */
	last_packet_ms = fileptr.ms;

	if (verbose > 0) {
		fprintf(stderr, "Playing %s\n", filename);
	}
	
	while (!fbs_at_eof(&fileptr)) {

		struct timeval tv, deadline;
		struct timezone tz;
		fd_set rfds;
		FD_ZERO (&rfds);
		FD_SET (clientr, &rfds);

		tv.tv_sec = (fileptr.ms - last_packet_ms) / 1000;
		tv.tv_usec = 1000 * ((fileptr.ms - last_packet_ms) % 1000);
		gettimeofday (&deadline, &tz);
		deadline.tv_sec += tv.tv_sec;
		deadline.tv_usec += tv.tv_usec;
		if (deadline.tv_usec >= 1000000) {
			deadline.tv_usec -= 1000000;
			deadline.tv_sec++;
		}

		/* FBS 1.0 only - guesstimate message boundaries.
		 * Heuristic: if the delay is >= 0.1s, we are at a message
		 * boundary.  THIS WILL BREAK FOR SLOW CONNECTIONS!
		 */
		if (finish && (tv.tv_sec || tv.tv_usec > 100000)) {
			ret = 1;
			goto out;
		}

		while (select(FD_SETSIZE, &rfds, NULL, NULL,
			      (!can_update || paused) ? NULL : &tv) != 0) {

			int stuff;
			stuff = handle_client_during_playback
				(clientr, cycle, pause, &client_fbf);
			if (stuff == -1)
				/* Connection closed. */
				goto out;
			if (stuff & 8) {
				can_update = 1;
			}
			if (stuff & 4) {
				/* Client changed pixel format on us.
				 * We could use this fact to optimize
				 * translations into copies if the new
				 * format is identical to the file's
				 * format, but we don't.
				 */
			}
			if (stuff & 2) {
				paused = 1 - paused;
			}
			if (stuff & 1) {
				/* user hit key to cycle to next file */

				if (fileptr.minor_version == 0) {
					/* FBS 1.0 - not sure if this
					 * is a message boundary, so
					 * set a flag and guesstimate
					 */
					finish = 1;
				} else {
					/* FBS 1.1 - we transfer entire
					 * server messages below and
					 * only come through this loop
					 * on a message boundary, so
					 * it's OK to just leave.
					 */
					ret = 1;
					goto out;
				}
			}

			/* Recalculate delay */
			gettimeofday (&tv, &tz);
			if (tv.tv_sec > deadline.tv_sec ||
			    (tv.tv_sec == deadline.tv_sec &&
			     tv.tv_usec >= deadline.tv_usec))
				/* Deadline already passed */
				break;

			tv.tv_sec = deadline.tv_sec - tv.tv_sec;
			tv.tv_usec = deadline.tv_usec - tv.tv_usec;
			if (tv.tv_usec < 0) {
				tv.tv_usec += 1000000;
				tv.tv_sec--;
			}
		}

		if (!can_update || paused)
			continue;

		last_packet_ms = fileptr.ms;

		if (fileptr.minor_version == 0) {

			/* We can't reliably find message boundaries in
			 * an FBS 1.0 file, so just send what we recorded
			 * verbatim and hope it makes sense to the client.
			 *
			 * It's also pretty pointless to try and stay
			 * synchronized by turning off 'can_update'
			 * (since we don't know when we've sent
			 * FramebufferUpdates), so just leave it on.
			 */

			do_write (clientw, fileptr.buf, fileptr.len);
			next_packet(&fileptr);

		} else {

			/* We translate an entire FramebufferUpdate
			 * here and _then_ come back through this loop
			 * to check timestamps and delay if needed,
			 * making no attempt to delay within a
			 * FramebufferUpdate.  This is noticeable if
			 * the session was recorded over a slow
			 * connection.  During playback, a large
			 * update that originally took some time to
			 * transfer will appear instantaneously and
			 * then be followed by a delay.  Doesn't seem
			 * important enough to fix.
			 */

			int length;

			switch (fileptr.buf[0]) {
			case 0:
				translate_FramebufferUpdate(&fileptr, outfile,
							    &server_fbf,
							    &client_fbf);
				can_update = 0;
				break;

			case 2:
				/* bell */
				fputc(get_uchar(&fileptr), outfile);
				break;

			case 3:
				/* ServerCutText */
				fput_long(get_long(&fileptr), outfile);
				fput_long(length = get_long(&fileptr),
					  outfile);
				while (length --) {
					fputc(get_uchar(&fileptr), outfile);
				}
				break;

			default:
				fprintf(stderr, "Unknown RFB message\n");
				break;
			}
		}

		fflush(outfile);
	}

	ret = 1;

 out:
	if (verbose > 0) {
		fprintf(stderr, "Playback (%s) done; ret=%d\n", filename, ret);
	}
	
	fclose(outfile);
	FBSclose(&fileptr);
	return ret;
}

/********** EXPORT **********/

/* We store the framebuffer as an array of PPM-format pixels to make it
 * easy to spit it out with a single write().  Since we're writing
 * about 30 frames per second (NTSC) on our output stream, this is
 * a big speed win over storing the framebuffer in RFB format and
 * converting everytime we write.
 */

struct pixel *framebuffer=NULL;

/* This function outputs the framebuffer as a PPM.  If outfilename is
 * NULL, we append to stdout.  Maybe I should fix this to use
 * non-buffered I/O exclusively.  As it is, it works on Linux; I just
 * make sure I fflush() before attempting a write().
 */

static int write_framebuffer_as_ppm (char *outfilename,
				     struct FramebufferFormat *fbf) {

	FILE * outfile;

	if (outfilename != NULL) {
		outfile = fopen(outfilename, "wb");
		if (!outfile) { perror("fopen"); return -1; }
	} else {
		outfile = stdout;
	}

	fprintf(outfile, "P6 %d %d 255\n", fbf->width, fbf->height);
	fflush(outfile);

	do_write (fileno(outfile), framebuffer,
		  fbf->width * fbf->height * sizeof(struct pixel));

	if (outfilename != NULL) fclose(outfile);

	return 0;
}

/* These are the functions that write into the framebuffer. */

void set_pixel(struct pixel *framebuffer, struct FramebufferFormat *fbf,
	       int x, int y, struct pixel *pptr)
{
	memcpy(&framebuffer[y*fbf->width + x], pptr, sizeof(struct pixel));
}

void copy_rect(struct pixel *framebuffer, struct FramebufferFormat *fbf,
	       int srcx, int srcy, int destx, int desty, int w, int h)
{
	int y;

	/* Brent learned through experience to be careful in this
	 * function about using memmove() instead of memcpy() and
	 * making sure we order the rows so we don't overwrite
	 * ourselves in the middle of a copy.
	 */

	if (desty <= srcy) {
		for (y = 0; y < h; y++) {
			memmove(&framebuffer[((desty + y) * fbf->width)+destx],
				&framebuffer[((srcy + y) * fbf->width) +srcx],
				w * sizeof(struct pixel));
		}
	} else {
		for (y = h-1; y >= 0; y--) {
			memmove(&framebuffer[((desty + y) * fbf->width)+destx],
				&framebuffer[((srcy + y) * fbf->width) +srcx],
				w * sizeof(struct pixel));
		}
	}
}

/* Profiling showed fill_rect() as a bottleneck, so I only use
 * set_pixel for the first line, then memcpy to copy the first line to
 * the subsequent lines.
 */

static void fill_rect(struct pixel *framebuffer, struct FramebufferFormat *fbf,
		      struct pixel *pixelptr,
		      int rectx, int recty, int rectw, int recth)
{
	int x, y;

	for (x = rectx; x < rectx+rectw; x++) {
	  set_pixel(framebuffer, fbf, x, recty, pixelptr);
	}

	for (y = recty+1; y < recty+recth; y++) {
	  memcpy(&framebuffer[y*fbf->width + rectx],
		 &framebuffer[recty*fbf->width + rectx],
		 rectw * sizeof(struct pixel));
	}
}

/* Output framerates for export function, specified as a fraction
 * (n/m) in frames per second.  I pulled them out of the mpeg2enc man
 * page.  "ntsc" is the only one I've actually used (to create DVD
 * content).
 *
 * The first framerate structure in the array is the default.
 */

struct framerate {
	char * name;
	int n;
	int m;
};

struct framerate preset_framerates[] = {
	{"ntsc", 30000, 1001},
	{"pal", 25, 1},
	{"film", 24, 1},
	{NULL, 0, 0}
};

/* process_FramebufferUpdate - process a single FramebufferUpdate
 * message that starts at the point 'file' is pointing to, and update
 * the in-memory 'framebuffer' array accordingly.  This is the
 * function that pulls together the two sets of functions above -
 * those that write into the framebuffer and those that read from the
 * recorded RFB session.
 */

/* hextile encoding is complex enough to get its own function */

static void process_hextile(FBSfile *file, struct FramebufferFormat *format,
			    int rectx, int recty, int rectw, int recth) {

	int subx, suby;
	int subencoding;
	int subrects, subrect;
	int x, y, xy, wh;
	struct pixel pix, background, foreground;

	for (suby=0; suby<recth; suby+=16) {
		for (subx=0; subx<rectw; subx+=16) {
			subencoding = get_uchar(file);
			if (subencoding & 1) {
				for (y = recty + suby;
				     (y < recty + suby + 16)
					     && (y < recty + recth); y++) {
					for (x = rectx + subx;
					     (x < rectx + subx + 16)
						     && (x < rectx + rectw);
					     x++) {
						get_pixel(file, format, &pix);
						set_pixel(framebuffer, format,
							  x, y, &pix);
					}
				}
			} else {
				if (subencoding & 2) {
					get_pixel(file, format, &background);
				}
				if (subencoding & 4) {
					get_pixel(file, format, &foreground);
				}
				fill_rect (framebuffer, format, &background,
					   rectx + subx, recty + suby,
					   (rectw - subx < 16)
					   ? rectw - subx : 16,
					   (recth - suby < 16)
					   ? recth - suby : 16);
				if (subencoding & 8) {
					subrects = get_uchar(file);
					for (subrect = 0; subrect < subrects;
					     subrect ++) {
						if (subencoding & 16) {
							get_pixel(file,
								  format,
								  &pix);
						}
						xy = get_uchar(file);
						wh = get_uchar(file);
						fill_rect (framebuffer,
							   format,
							   subencoding & 16 ?
							   &pix : &foreground,
							   rectx + subx
							   + (xy >> 4),
							   recty + suby
							   + (xy & 15),
							   (wh >> 4) + 1,
							   (wh & 15) + 1);
					}
				}
			}
		}
	}
}

static void process_FramebufferUpdate(FBSfile *file,
				      struct FramebufferFormat *format)
{
	int rect, subrect, x, y;
	int srcx, srcy;
	uint16_t nrects;
	uint16_t rectx, recty, rectw, recth;
	uint32_t type;
	uint32_t nsubrects;
	uint16_t subx, suby, subw, subh;
	struct pixel pix;

	get_short(file);
	nrects = get_short(file);

	if (verbose > 2)
		fprintf(stderr, "Framebuffer update (%d rects)\n", nrects);

	for (rect = 0; rect < nrects; rect ++) {

		rectx = get_short(file);
		recty = get_short(file);
		rectw = get_short(file);
		recth = get_short(file);
		type = get_long(file);

		if (verbose > 3)
			fprintf(stderr, "rect %d: (%d,%d) %dx%d type %d\n",
				rect, rectx, recty, rectw, recth, type);

		switch (type) {
		case 0:
			/* raw */
			for (y = recty; y < recty+recth; y++) {
				for (x = rectx; x < rectx+rectw; x++) {
					get_pixel(file, format, &pix);
					set_pixel(framebuffer, format,
						  x, y, &pix);
				}
			}
			break;

		case 1:
			/* copy rect */
			srcx = get_short(file);
			srcy = get_short(file);
			copy_rect(framebuffer, format,
				  srcx, srcy, rectx, recty, rectw, recth);
			break;

		case 2:
			/* RRE */
			nsubrects = get_long(file);
			get_pixel(file, format, &pix);
			fill_rect(framebuffer, format, &pix,
				  rectx, recty, rectw, recth);

			for (subrect=0; subrect<nsubrects; subrect++) {
				get_pixel(file, format, &pix);
				subx = get_short(file);
				suby = get_short(file);
				subw = get_short(file);
				subh = get_short(file);
				fill_rect(framebuffer, format, &pix,
					  rectx + subx, recty + suby,
					  subw, subh);
			}
			break;

		case 4:
			/* CoRRE */
			nsubrects = get_long(file);
			get_pixel(file, format, &pix);
			fill_rect(framebuffer, format, &pix,
				  rectx, recty, rectw, recth);

			for (subrect=0; subrect<nsubrects; subrect++) {
				get_pixel(file, format, &pix);
				subx = get_uchar(file);
				suby = get_uchar(file);
				subw = get_uchar(file);
				subh = get_uchar(file);
				fill_rect(framebuffer, format, &pix,
					  rectx + subx, recty + suby,
					  subw, subh);
			}
			break;

		case 5:
			process_hextile (file, format,
					 rectx, recty, rectw, recth);
			break;

		default:

			/* We don't understand the pixel encoding.
			 * Maybe we should just bail here, but try to
			 * keep going.  Skip to next packet, and do an
			 * immediate return to halt processing of this
			 * FramebufferUpdate.
			 */

			fprintf(stderr, "Unknown pixel encoding (%d)\n", type);
			next_packet(file);
			return;

		}
	}

}

/* export() - called from main() runs through a recorded file (in FBS
 * format) from beginning to end, spitting out PPM frames to stdout at
 * a framerate specified as a fraction (n/m) in frames per second.
 */

static int export (const char *filename, int framerate_n, int framerate_m)
{
	FBSfile fileptr;
	struct FramebufferFormat fbfs;
	struct FramebufferFormat *format = &fbfs;
	int last_frame = 0;
	int length;

	if (FBSopen(filename, &fileptr) == -1) {
		return -1;
	}

	if (fileptr.minor_version == 0) {
		fprintf(stderr,	"Warning: "
			"FBS version 1.0 file with ambiguous pixel format\n");
	}

	if (get_initial_RFB_handshake(&fileptr, format) == -1) {
		FBSclose(&fileptr);
		return -1;
	}

	framebuffer = (struct pixel *)
		malloc(format->width * format->height * sizeof(struct pixel));
	if (framebuffer == NULL) {
		fprintf (stderr,"couldn't malloc framebuffer");
		FBSclose(&fileptr);
		return -1;
	}

	while (!fbs_at_eof(&fileptr)) {

		switch (fileptr.buf[0]) {
		case 0:
			process_FramebufferUpdate(&fileptr, format);

			/* fileptr.ms has now advanced to the
			 * timestamp on the next byte after the
			 * FramebufferUpdate we just processed,
			 * so see if we need to spit out any frames.
			 *
			 * We don't do anything at timestamp 0.  We
			 * output frame 1 at timestamp m/n sec, and so
			 * on.  Maybe we should output a "frame 0" as
			 * soon as we've processed the first
			 * framebuffer update, I don't know.
			 *
			 * And I use floating point math simply
			 * because fileptr.ms * 30000 (NTSC's
			 * framerate_n) overflows a 32-bit long at
			 * around (2^32)/30000/1000 = 143 seconds.
			 */

			while (1000.0 * (last_frame + 1) * framerate_m
			       < (double) fileptr.ms * framerate_n) {

				write_framebuffer_as_ppm(NULL, format);
				last_frame ++;
				if ((verbose > 0) &&
				    ((verbose > 1) || (last_frame % 100) == 0))
					fprintf(stderr, "Encoded frame %d\n",
						last_frame);
			}

			break;

		case 2:
			/* Bell */
			get_uchar(&fileptr);
			break;

		case 3:
			/* ServerCutText */
			get_long(&fileptr);
			length = get_long(&fileptr);
			get_bytes(&fileptr, NULL, length);
			break;

		default:

			/* If we couldn't understand the server
			 * message, jump to the start of the next FBS
			 * packet and hope it's something we do
			 * understand.
			 */

			fprintf(stderr, "Unknown RFB message\n");
			next_packet(&fileptr);
			break;
		}
	}

	/* Normal return */
	FBSclose(&fileptr);
	return 0;
}

/********** MAIN AND FRIENDS **********/

static void version (void)
{
	fprintf (stderr, "rfbproxy version %s\n", VERSION);
}

static void usage (const char *name)
{
	fprintf (stderr,
		 "usage: %s [OPTIONS] ACTION files\n"
		 "\nACTION is one of:\n"
		 " -r, --record\n"
		 "               Record RFB communications and store them in\n"
		 "               the file.\n"
		 " -p, --playback\n"
		 "               Play back the RFB communications that were\n"
		 "               captured to the file or files.\n"
		 " -x, --export\n"
		 "               Export recorded RFB communication as PPMs\n"
		 "               First step in creating an MPEG.\n"
		 " --version\n"
		 "               Report program version (" VERSION ")\n"
		 "where OPTIONS are:\n\n"
		 " -c, --stdout  Use stdin and stdout for communications\n"
		 "               with the client. Useful in conjunction\n"
		 "               with inetd.\n"
		 " -l, --loop    (playback only) When file is finished,\n"
		 "               replay from first FrameBufferUpdate\n"
		 " -d, --date    (record only) Append Date to end of filename\n"
		 " -s, --shared  (record only) attach to a shared session\n"
		 "               incompatible with --stdout\n"
		 " -v, --verbose increase verbosity\n"
		 " --pause=key   (playback only) When the key is pressed,\n"
		 "               playback will be paused until it is pressed\n"
		 "               again.\n"
		 " --cycle=key   (playback only) When multiple files are specified\n"
		 "               pressing the key will cycle between them.\n"
		 " --type=[screen|events]\n"
		 "               (record only) Capture either screen updates\n"
		 "               (\"screen\") or keyboard/mouse events (\"events\").\n"
		 "               The default is \"screen\".\n"
		 " --framerate=[ntsc|pal|film|m/n]\n"
		 "               (export only) Specify framerate by name\n"
		 "               or rational fraction (frames per second)\n"
		 " :n            Occupy VNC display localhost:n (not valid with\n"
		 "               -c option). The default is \""
		 DEFAULT_DISPLAY "\".\n"
		 " --server=[server]:display\n"
		 "               (record only) Use specified VNC server. The\n"
		 "               default is \"" DEFAULT_SERVER "\".\n"
		 " --password=yourPassword\n"
		 "               (record only) Specify a password to use when connecting to a shared VNC server.\n"
		 " --recording-lock-file=filename\n"
		 "               (record only) A file to populate with the PID of the process whilst recording (disappears on a successful kill).\n",
		 name);
	exit (1);
}

int accept_connection (int port)
{
	int bound;
	int sock;
	struct sockaddr_in sin;
	int on = 1;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons (VNC_BASE + port);
	bound = socket (AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (bound < 0) {
		perror ("socket");
		exit (1);
	}
	setsockopt (bound, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));
	if (bind (bound, (struct sockaddr *) &sin,
		  sizeof (struct sockaddr_in))) {
		perror ("bind");
		exit (1);
	}
	listen (bound, 1);
	sock = accept (bound, NULL, 0);
	close (bound);
	return sock;
}

int main (int argc, char *argv[])
{
	int use_stdout = 0;
	int loop = 0;
	int appenddate = 0;
	int shared_session = 0;
	const char **file = NULL;
	int files = 0;
	char action = '\0';
	char type = '\0';
	char *server = NULL;
	char *display = NULL;
	char *vnc_password = NULL;
	char *recording_lock_file = NULL;
	int clientr, clientw;
	struct sockaddr_in server_addr;
	int orig_optind;
	int cycle = 0, pause = 0;
	struct framerate *framerate = &preset_framerates[0];

	/* Options */
	for (;;) {
		static struct option long_options[] = {
			{"playback", 0, 0, 'p'},
			{"record", 0, 0, 'r'},
			{"export", 0, 0, 'x'},
			{"type", 1, 0, 't'},
			{"date", 0, 0, 'd'},
			{"loop", 0, 0, 'l'},
			{"stdout", 0, 0, 'c'},
			{"shared", 0, 0, 's'},
			{"server", 1, 0, 'S'},
			{"framerate", 1, 0, 'F'},
			{"help", 0, 0, 'h'},
			{"version", 0, 0, 'V'},
			{"verbose", 0, 0, 'v'},
			{"pause", 1, 0, 'P'},
			{"cycle", 1, 0, 'C'},
			{"password", 1, 0, 'W'},
			{"recording-lock-file", 1, 0, 'X'},
			{0, 0, 0, 0}
		};
		int l;
		int c = getopt_long (argc, argv, "prxcldsv",
				     long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
			char *p;
		case 'P':
			pause = strtoul (optarg, &p, 16);
			if (optarg == p)
				pause = *optarg;
			break;
		case 'C':
			cycle = strtoul (optarg, &p, 16);
			if (optarg == p)
				cycle = *optarg;
			break;
		case 'V':
			version ();
			exit (0);
		case 'h':
			version ();
			usage (argv[0]);
		case 'c':
			if (use_stdout)
				usage (argv[0]);
			use_stdout = 1;
			break;
		case 'l':
			if (loop)
				usage (argv[0]);
			loop = 1;
			break;
		case 'd':
			if (appenddate)
				usage (argv[0]);
			appenddate = 1;
			break;
		case 't':
			if (type)
				usage (argv[0]);
			l = strlen (optarg);
			if (!strncmp (optarg, "screen", l))
				type = 's';
			else if (!strncmp (optarg, "events", l))
				type = 'e';
			else usage (argv[0]);
			break;
        case 'W':
			if (vnc_password)
				usage (argv[0]);
			vnc_password = optarg;
			break;
		case 'X':
			if (recording_lock_file)
				usage (argv[0]);
			recording_lock_file = optarg;
			break;

		case 'S':
			if (server)
				usage (argv[0]);
			server = optarg;
			break;
		case 's':
			if (shared_session)
				usage (argv[0]);
			shared_session = 1;
			break;
		case 'F':
			for (framerate = preset_framerates;
			     framerate->name != NULL;
			     framerate ++) {
				if (!strcmp(framerate->name, optarg)) break;
			}
			if (framerate->name == NULL) {
				framerate->m = 1;
				if (sscanf(optarg, "%d%*[:/]%d",
					   &framerate->n,&framerate->m) == 0) {
					usage(argv[0]);
				}
			}
			break;
		case 'v':
			verbose ++;
			break;
		case 'p':
		case 'r':
		case 'x':
			if (action)
				usage (argv[0]);
			action = c;
			break;
		}
	}

	orig_optind = optind;
	for (; optind < argc; optind++) {
		if (!display && argv[optind][0] == ':') {
			display = argv[optind];
			continue;
		}

		files++;
	}
	file = malloc ((files + 1) * sizeof (char *));
	if (!file) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}
	files = 0;
	for (optind = orig_optind; optind < argc; optind++)
		if (argv[optind][0] != ':')
			file[files++] = argv[optind];
	file[files] = NULL;

	/* Invalid option combinations */
	if (!action ||
	    (loop && action != 'p') ||
	    (type && action != 'r') ||
	    (server && action != 'r') ||
	    (shared_session && action != 'r') ||
	    (shared_session && type == 'e') ||
	    (shared_session && use_stdout) ||
	    ((framerate != &preset_framerates[0]) && action != 'x') ||
	    (use_stdout && display))
		usage (argv[0]);

	if (files < 1)
		/* No files specified */
		usage (argv[0]);

	/* Defaults */
	if (!server)
		server = strdup (DEFAULT_SERVER);
	if (!display)
		display = strdup (DEFAULT_DISPLAY);
	if (!type)
		type = 's';

	if (action == 'r') {
		int port;
		char *end;
		char *cl = strchr (server, ':');
		if (files > 1)
			/* Can't record to more than one file */
			usage (argv[0]);
		if (!cl)
			usage (argv[0]);
		*cl++ = '\0';
		port = VNC_BASE + strtoul (cl, &end, 10);
		if (cl == end)
			usage (argv[0]);
		server_addr.sin_family = AF_INET;
		if (!server[0])
			server_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
		else {
			struct hostent *hp;
			if ((server_addr.sin_addr.s_addr =
			     inet_addr (server)) == -1) {
				hp = gethostbyname (server);
				if (!hp) {
					perror (server);
					exit (1);
				}
				memcpy (&server_addr.sin_addr.s_addr,
					hp->h_addr_list[0],
					hp->h_length);
			}
		}
		server_addr.sin_port = htons (port);
	}

	/* Export */
	if (action == 'x') {
		int file_to_export;

		for (file_to_export = 0;
		     file_to_export < files; file_to_export++) {
			export(file[file_to_export],
			       framerate->n, framerate->m);
		}

		return 0;
	}

	/* Record or playback - get client's file descriptors */
	if (use_stdout) {
		clientr = fileno (stdin);
		clientw = fileno (stdout);
	} else if (!shared_session) {
		unsigned long port;
		char *end;
		display++;
		port = strtoul (display, &end, 10);
		if (display == end)
			usage (argv[0]);
		clientr = clientw = accept_connection (port);
	} else {
		/* Above we made sure that shared_session was only
		 * set if we were recording, so the only case we've
		 * got left is a shared_session record, which doesn't
		 * talk directly to a client at all.
		 */
		clientr = clientw = -1;
	}

	/* Do it */
	if (action == 'r') {
		record (file[0], clientr, clientw, server_addr, type == 'e', appenddate, shared_session, vnc_password, recording_lock_file);
	} else {
		int file_to_play = 0;
		int looping = 0;
		while (playback (file[file_to_play],
				 clientr, clientw, looping,
				 cycle, pause) > 0) {
			file_to_play++;
			if (file_to_play == files) {
				if (!loop)
					break;
				file_to_play = 0;
			}
			looping = 1;
		}
	}

	/* Clean up */
	if (!use_stdout)
		close (clientr);

	return 0;
}
