/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `event' library (-levent). */
#define HAVE_LIBEVENT 1

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
 to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
 and to 0 otherwise. */
#define HAVE_REALLOC 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
 */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libwebsock"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "payden@paydensutherland.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libwebsock"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libwebsock 1.0.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libwebsock"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0.1"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "1.0.1"

/* Define if building SSL support */
#define WEBSOCK_HAVE_SSL 0

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */


//this bit hides differences between systems on big-endian conversions
#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be32toh(x) betoh32(x)
#  define be64toh(x) betoh64(x)
#elif defined(_WIN32)
#  define be16toh(x) lws_be16toh(x)
#  define be64toh(x) lws_be16toh(x)
#  define htobe16(x) lws_htobe16(x)
#  define htobe64(x) lws_htobe64(x)
#endif

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif	/* __APPLE__ */

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#include <stdint.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <wchar.h>
#include <errno.h>
#ifdef WEBSOCK_HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>
#endif

#include <unistd.h>
#include <csignal>

#define PORT_STRLEN 12
#define LISTEN_BACKLOG 10
#define FRAME_CHUNK_LENGTH 1024
#define MASK_LENGTH 4

#define WS_FRAGMENT_FIN (1 << 7)

#define WS_OPCODE_CONTINUE 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xa

#define WS_CLOSE_NORMAL 1000
#define WS_CLOSE_GOING_AWAY 1001
#define WS_CLOSE_PROTOCOL_ERROR 1002
#define WS_CLOSE_NOT_ALLOWED 1003
#define WS_CLOSE_RESERVED 1004
#define WS_CLOSE_NO_CODE 1005
#define WS_CLOSE_DIRTY 1006
#define WS_CLOSE_WRONG_TYPE 1007
#define WS_CLOSE_POLICY_VIOLATION 1008
#define WS_CLOSE_MESSAGE_TOO_BIG 1009
#define WS_CLOSE_UNEXPECTED_ERROR 1011


#define STATE_SHOULD_CLOSE (1 << 0)
#define STATE_SENT_CLOSE_FRAME (1 << 1)
#define STATE_CONNECTING (1 << 2)
#define STATE_IS_SSL (1 << 3)
#define STATE_CONNECTED (1 << 4)
#define STATE_SENDING_FRAGMENT (1 << 5)
#define STATE_RECEIVING_FRAGMENT (1 << 6)



#ifndef TYPES_H_
#define TYPES_H_

enum WS_FRAME_STATE {
    sw_start = 0,
    sw_got_two,
    sw_got_short_len,
    sw_got_full_len,
    sw_loaded_mask
};

typedef struct _libwebsock_frame {
    unsigned int fin;
    unsigned int opcode;
    unsigned int mask_offset;
    unsigned int payload_offset;
    unsigned int rawdata_idx;
    unsigned int rawdata_sz;
    unsigned int payload_len_short;
    unsigned long long payload_len;
    char *rawdata;
    struct _libwebsock_frame *next_frame;
    struct _libwebsock_frame *prev_frame;
    unsigned char mask[4];
    enum WS_FRAME_STATE state;
} libwebsock_frame;

typedef struct _libwebsock_string {
    char *data;
    int length;
    int idx;
    int data_sz;
} libwebsock_string;

typedef struct _libwebsock_message {
    unsigned int opcode;
    unsigned long long payload_len;
    char *payload;
} libwebsock_message;

typedef struct _libwebsock_close_info {
    unsigned short code;
    char reason[124];
} libwebsock_close_info;

typedef struct _libwebsock_client_state {
    int sockfd;
    int flags;
    void *data;
    libwebsock_frame *current_frame;
    struct sockaddr_storage *sa;
    struct bufferevent *bev;
    int (*onmessage)(struct _libwebsock_client_state *, libwebsock_message *);
    int (*control_callback)(struct _libwebsock_client_state *, libwebsock_frame *);
    int (*onopen)(struct _libwebsock_client_state *);
    int (*onclose)(struct _libwebsock_client_state *);
#ifdef WEBSOCK_HAVE_SSL
    SSL *ssl;
#endif
    libwebsock_close_info *close_info;
} libwebsock_client_state;

typedef struct _libwebsock_context {
    int running;
    int ssl_init;
    struct event_base *base;
    int (*onmessage)(libwebsock_client_state *, libwebsock_message *);
    int (*control_callback)(libwebsock_client_state *, libwebsock_frame *);
    int (*onopen)(libwebsock_client_state *);
    int (*onclose)(libwebsock_client_state *);
} libwebsock_context;


typedef struct _libwebsock_fragmented {
    char *send;
    char *queued;
    unsigned int send_len;
    unsigned int queued_len;
    struct _libwebsock_client_state *state;
} libwebsock_fragmented;

#ifdef WEBSOCK_HAVE_SSL
typedef struct _libwebsock_ssl_event_data {
    SSL_CTX *ssl_ctx;
    libwebsock_context *ctx;
} libwebsock_ssl_event_data;
#endif

#ifndef API_H_
#define API_H_


int libwebsock_close(libwebsock_client_state *state);
int libwebsock_close_with_reason(libwebsock_client_state *state, unsigned short code, const char *reason);
int libwebsock_send_binary(libwebsock_client_state *state, char *in_data, unsigned long long payload_len);
int libwebsock_send_text(libwebsock_client_state *state, char *strdata);
int libwebsock_send_text_with_length(libwebsock_client_state *state, char *strdata, unsigned long long payload_len);
void libwebsock_wait(libwebsock_context *ctx);
void libwebsock_bind(libwebsock_context *ctx, char *listen_host, unsigned int port);
libwebsock_context *libwebsock_init(void);

#ifdef WEBSOCK_HAVE_SSL
void libwebsock_bind_ssl(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile);
void libwebsock_bind_ssl_real(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile, char *chainfile);
#endif

#endif /* API_H_ */
#ifndef BASE64_H_
#define BASE64_H_

int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);
void _base64_encode_triple(unsigned char triple[3], char result[4]);
int _base64_char_value(char base64char);
int _base64_decode_triple(char quadruple[4], unsigned char *result);
size_t base64_decode(char *source, unsigned char *target, size_t targetlen);

#endif

/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef DEFAULT_CALLBACKS_H_
#define DEFAULT_CALLBACKS_H_

int libwebsock_default_onclose_callback(libwebsock_client_state *state);
int libwebsock_default_onopen_callback(libwebsock_client_state *state);
int libwebsock_default_onmessage_callback(libwebsock_client_state *state, libwebsock_message *msg);
int libwebsock_default_control_callback(libwebsock_client_state *state, libwebsock_frame *ctl_frame);


#endif /* DEFAULT_CALLBACKS_H_ */
/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef FRAMES_H_
#define FRAMES_H_

inline void libwebsock_frame_act(libwebsock_client_state *state, libwebsock_frame *frame);
void libwebsock_free_all_frames(libwebsock_client_state *state);
void libwebsock_cleanup_frames(libwebsock_frame *first);
void libwebsock_dump_frame(libwebsock_frame *frame);
int libwebsock_read_header(libwebsock_frame *frame);


#endif /* FRAMES_H_ */
/*
 *  sha1.h
 *
 *  Copyright (C) 1998, 2009
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved
 *
 *****************************************************************************
 *  $Id: sha1.h 12 2009-06-22 19:34:25Z paulej $
 *****************************************************************************
 *
 *  Description:
 *      This class implements the Secure Hashing Standard as defined
 *      in FIPS PUB 180-1 published April 17, 1995.
 *
 *      Many of the variable names in the SHA1Context, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */

#ifndef _SHA1_H_
#define _SHA1_H_

/* 
 *  This structure will hold context information for the hashing
 *  operation
 */
typedef struct SHA1Context
{
    unsigned Message_Digest[5]; /* Message Digest (output)          */

    unsigned Length_Low;        /* Message length in bits           */
    unsigned Length_High;       /* Message length in bits           */

    unsigned char Message_Block[64]; /* 512-bit message blocks      */
    int Message_Block_Index;    /* Index into message block array   */

    int Computed;               /* Is the digest computed?          */
    int Corrupted;              /* Is the message digest corruped?  */
} SHA1Context;

/*
 *  Function Prototypes
 */
void SHA1Reset(SHA1Context *);
int SHA1Result(SHA1Context *);
void SHA1Input( SHA1Context *,
                const unsigned char *,
                unsigned);

#endif
/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */



#endif /* TYPES_H_ */
/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef UTF_H_
#define UTF_H_

#include <stdint.h>

uint32_t inline decode(uint32_t *state, uint32_t *codep, uint32_t byte);


#endif /* UTF_H_ */
/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef UTIL_H_
#define UTIL_H_
#include <stdint.h>

int validate_utf8_sequence(uint8_t *s);

#endif /* UTIL_H_ */
/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


//function defs

int libwebsock_send_fragment(libwebsock_client_state *state, const char *data, unsigned long long len, int flags);
void libwebsock_send_cleanup(const void *data, size_t len, void *arg);
void libwebsock_shutdown(libwebsock_client_state *state);
void libwebsock_populate_close_info_from_frame(libwebsock_close_info **info, libwebsock_frame *close_frame);
void libwebsock_fail_connection(libwebsock_client_state *state, unsigned short close_code);
void libwebsock_cleanup_context(libwebsock_context *ctx);
void libwebsock_handle_signal(evutil_socket_t sig, short event, void *ptr);
void libwebsock_handle_control_frame(libwebsock_client_state *state, libwebsock_frame *ctl_frame);
void libwebsock_dispatch_message(libwebsock_client_state *state, libwebsock_frame *current);
void libwebsock_handle_accept(evutil_socket_t listener, short event, void *arg);
void libwebsock_handle_send(struct bufferevent *bev, void *ptr);
void libwebsock_handle_recv(struct bufferevent *bev, void *ptr);
void libwebsock_handle_client_event(libwebsock_context *ctx, libwebsock_client_state *state);
void libwebsock_do_read(struct bufferevent *bev, void *ptr);
void libwebsock_do_event(struct bufferevent *bev, short event, void *ptr);
void libwebsock_handshake_finish(struct bufferevent *bev, libwebsock_client_state *state);
void libwebsock_handshake(struct bufferevent *bev, void *ptr);
void libwebsock_fragmented_add(libwebsock_fragmented *frag, char *buf, unsigned int len);
void libwebsock_fragmented_finish(libwebsock_fragmented *frag);
libwebsock_fragmented *libwebsock_fragmented_new(libwebsock_client_state *state);

#ifdef WEBSOCK_HAVE_SSL
void libwebsock_handle_accept_ssl(evutil_socket_t listener, short event, void *arg);
#endif

