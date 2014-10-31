
#include "websocket.h"
#include <string>
#include <sstream>

void libwebsock_dump_frame(libwebsock_frame *frame) {
    int i;
    fprintf(stderr, "FIN: %d\n", frame->fin);
    fprintf(stderr, "Opcode: %d\n", frame->opcode);
    fprintf(stderr, "mask_offset: %d\n", frame->mask_offset);
    fprintf(stderr, "payload_offset: %d\n", frame->payload_offset);
    fprintf(stderr, "rawdata_idx: %d\n", frame->rawdata_idx);
    fprintf(stderr, "rawdata_sz: %d\n", frame->rawdata_sz);
    fprintf(stderr, "payload_len: %llu\n", frame->payload_len);
    fprintf(stderr, "Has previous frame: %d\n", frame->prev_frame != NULL ? 1 : 0);
    fprintf(stderr, "Has next frame: %d\n", frame->next_frame != NULL ? 1 : 0);
    fprintf(stderr, "Raw data:\n");
    fprintf(stderr, "%02x", *(frame->rawdata) & 0xff);
    for (i = 1; i < frame->rawdata_idx; i++) {
        fprintf(stderr, ":%02x", *(frame->rawdata + i) & 0xff);
    }
    fprintf(stderr, "\n");
}

int libwebsock_close(libwebsock_client_state *state) {
    return libwebsock_close_with_reason(state, WS_CLOSE_NORMAL, NULL );
}

int libwebsock_close_with_reason(libwebsock_client_state *state, unsigned short code, const char *reason) {
    unsigned long long len;
    unsigned short code_be;
    int ret;
    char buf[128]; //w3 spec on WebSockets API (http://dev.w3.org/html5/websockets/) says reason shouldn't be over 123 bytes.  I concur.
    len = 2;
    code_be = htobe16(code);
    memcpy(buf, &code_be, 2);
    if (reason) {
        len += snprintf(buf + 2, 124, "%s", reason);
    }
    int flags = WS_FRAGMENT_FIN | WS_OPCODE_CLOSE;
    ret = libwebsock_send_fragment(state, buf, len, flags);
    state->flags |= STATE_SENT_CLOSE_FRAME;
    return ret;
}

int libwebsock_send_text_with_length(libwebsock_client_state *state, char *strdata, unsigned long long payload_len) {
    int flags = WS_FRAGMENT_FIN | WS_OPCODE_TEXT;
    return libwebsock_send_fragment(state, strdata, payload_len, flags);
}

int libwebsock_send_text(libwebsock_client_state *state, char *strdata) {
    unsigned long long len = strlen(strdata);
    int flags = WS_FRAGMENT_FIN | WS_OPCODE_TEXT;
    return libwebsock_send_fragment(state, strdata, len, flags);
}

int libwebsock_send_binary(libwebsock_client_state *state, char *in_data, unsigned long long payload_len) {
    int flags = WS_FRAGMENT_FIN | WS_OPCODE_BINARY;
    return libwebsock_send_fragment(state, in_data, payload_len, flags);
}

void libwebsock_wait(libwebsock_context *ctx) {
    struct event *sig_event;
    sig_event = evsignal_new(ctx->base, SIGINT, libwebsock_handle_signal, (void *)ctx);
    event_add(sig_event, NULL );
    ctx->running = 1;
    event_base_dispatch(ctx->base);
    ctx->running = 0;
    event_free(sig_event);
}

void libwebsock_bind(libwebsock_context *ctx, char *listen_host, unsigned int port) {
    struct addrinfo hints, *servinfo, *p;
    struct event *listener_event;
    
    evutil_socket_t sockfd;
    int yes = 1;
    memset(&hints, 0, sizeof(struct addrinfo));
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    
    
    char portc[6];
    memset(portc, 0, 6 * sizeof(char));
    sprintf(portc, "%d", port);
    
    if ((getaddrinfo(listen_host, portc, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo failed during libwebsock_bind.\n");
        free(ctx);
        exit(-1);
    }
    for (p = servinfo; p != NULL ; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }
        
        evutil_make_socket_nonblocking(sockfd);
        
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
        }
        
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("bind");
            close(sockfd);
            continue;
        }
        break;
    }
    
    if (p == NULL) {
        fprintf(stderr, "Failed to bind to address and port.  Exiting.\n");
        free(ctx);
        exit(-1);
    }
    
    freeaddrinfo(servinfo);
    
    if (listen(sockfd, LISTEN_BACKLOG) == -1) {
        perror("listen");
        exit(-1);
    }
    
    listener_event = event_new(ctx->base, sockfd, EV_READ | EV_PERSIST, libwebsock_handle_accept, (void *) ctx);
    event_add(listener_event, NULL );
}

libwebsock_context * libwebsock_init(void) {
    libwebsock_context *ctx;
    ctx = (libwebsock_context *) malloc(sizeof(libwebsock_context));
    if (!ctx) {
        fprintf(stderr, "Unable to allocate memory for libwebsock context.\n");
        return ctx;
    }
    
    
    memset(ctx, 0, sizeof(libwebsock_context));
    
    ctx->onclose = libwebsock_default_onclose_callback;
    ctx->onopen = libwebsock_default_onopen_callback;
    ctx->control_callback = libwebsock_default_control_callback;
    ctx->onmessage = libwebsock_default_onmessage_callback;
    
    ctx->base = event_base_new();
    if (!ctx->base) {
        free(ctx);
        fprintf(stderr, "Unable to create new event base.\n");
        return NULL;
    }
    
    return ctx;
}




/**
 * characters used for Base64 encoding
 */
const char *BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * encode three bytes using base64 (RFC 3548)
 *
 * @param triple three bytes that should be encoded
 * @param result buffer of four characters where the result is stored
 */
void _base64_encode_triple(unsigned char triple[3], char result[4]) {
    int tripleValue, i;
    
    tripleValue = triple[0];
    tripleValue *= 256;
    tripleValue += triple[1];
    tripleValue *= 256;
    tripleValue += triple[2];
    
    for (i=0; i<4; i++) {
        result[3-i] = BASE64_CHARS[tripleValue%64];
        tripleValue /= 64;
    }
}

/**
 * encode an array of bytes using Base64 (RFC 3548)
 *
 * @param source the source buffer
 * @param sourcelen the length of the source buffer
 * @param target the target buffer
 * @param targetlen the length of the target buffer
 * @return 1 on success, 0 otherwise
 */
int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen) {
    /* check if the result will fit in the target buffer */
    if ((sourcelen+2)/3*4 > targetlen-1)
        return 0;
    
    /* encode all full triples */
    while (sourcelen >= 3)
    {
        _base64_encode_triple(source, target);
        sourcelen -= 3;
        source += 3;
        target += 4;
    }
    
    /* encode the last one or two characters */
    if (sourcelen > 0)
    {
        unsigned char temp[3];
        memset(temp, 0, sizeof(temp));
        memcpy(temp, source, sourcelen);
        _base64_encode_triple(temp, target);
        target[3] = '=';
        if (sourcelen == 1)
            target[2] = '=';
        
        target += 4;
    }
    
    /* terminate the string */
    target[0] = 0;
    
    return 1;
}

/**
 * determine the value of a base64 encoding character
 *
 * @param base64char the character of which the value is searched
 * @return the value in case of success (0-63), -1 on failure
 */
int _base64_char_value(char base64char)  {
    if (base64char >= 'A' && base64char <= 'Z')
        return base64char-'A';
    if (base64char >= 'a' && base64char <= 'z')
        return base64char-'a'+26;
    if (base64char >= '0' && base64char <= '9')
        return base64char-'0'+2*26;
    if (base64char == '+')
        return 2*26+10;
    if (base64char == '/')
        return 2*26+11;
    return -1;
}

/**
 * decode a 4 char base64 encoded byte triple
 *
 * @param quadruple the 4 characters that should be decoded
 * @param result the decoded data
 * @return lenth of the result (1, 2 or 3), 0 on failure
 */
int _base64_decode_triple(char quadruple[4], unsigned char *result)
{
    int i, triple_value, bytes_to_decode = 3, only_equals_yet = 1;
    int char_value[4];
    
    for (i=0; i<4; i++)
        char_value[i] = _base64_char_value(quadruple[i]);
    
    /* check if the characters are valid */
    for (i=3; i>=0; i--)
    {
        if (char_value[i]<0)
        {
            if (only_equals_yet && quadruple[i]=='=')
            {
                /* we will ignore this character anyway, make it something
                 * that does not break our calculations */
                char_value[i]=0;
                bytes_to_decode--;
                continue;
            }
            return 0;
        }
        /* after we got a real character, no other '=' are allowed anymore */
        only_equals_yet = 0;
    }
    
    /* if we got "====" as input, bytes_to_decode is -1 */
    if (bytes_to_decode < 0)
        bytes_to_decode = 0;
    
    /* make one big value out of the partial values */
    triple_value = char_value[0];
    triple_value *= 64;
    triple_value += char_value[1];
    triple_value *= 64;
    triple_value += char_value[2];
    triple_value *= 64;
    triple_value += char_value[3];
    
    /* break the big value into bytes */
    for (i=bytes_to_decode; i<3; i++)
        triple_value /= 256;
    for (i=bytes_to_decode-1; i>=0; i--)
    {
        result[i] = triple_value%256;
        triple_value /= 256;
    }
    
    return bytes_to_decode;
}

/**
 * decode base64 encoded data
 *
 * @param source the encoded data (zero terminated)
 * @param target pointer to the target buffer
 * @param targetlen length of the target buffer
 * @return length of converted data on success, -1 otherwise
 */
size_t base64_decode(char *source, unsigned char *target, size_t targetlen)  {
    char *src, *tmpptr;
    char quadruple[4];
    unsigned char tmpresult[3];
    int i, tmplen = 3;
    size_t converted = 0;
    
    /* concatinate '===' to the source to handle unpadded base64 data */
    src = (char *)malloc(strlen(source)+5);
    if (src == NULL)
        return -1;
    strcpy(src, source);
    strcat(src, "====");
    tmpptr = src;
    
    /* convert as long as we get a full result */
    while (tmplen == 3)
    {
        /* get 4 characters to convert */
        for (i=0; i<4; i++)
        {
            /* skip invalid characters - we won't reach the end */
            while (*tmpptr != '=' && _base64_char_value(*tmpptr)<0)
                tmpptr++;
            
            quadruple[i] = *(tmpptr++);
        }
        
        /* convert the characters */
        tmplen = _base64_decode_triple(quadruple, tmpresult);
        
        /* check if the fit in the result buffer */
        if (targetlen < tmplen)
        {
            free(src);
            return -1;
        }
        
        /* put the partial result in the result buffer */
        memcpy(target, tmpresult, tmplen);
        target += tmplen;
        targetlen -= tmplen;
        converted += tmplen;
    }
    
    free(src);
    return converted;
}

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


int
libwebsock_default_onclose_callback(libwebsock_client_state *state)
{
    fprintf(stderr, "Closing connection with socket descriptor: %d\n", state->sockfd);
    return 0;
}

int
libwebsock_default_onopen_callback(libwebsock_client_state *state)
{
    fprintf(stderr, "New connection with socket descriptor: %d\n", state->sockfd);
    return 0;
}

int
libwebsock_default_onmessage_callback(libwebsock_client_state *state, libwebsock_message *msg)
{
    libwebsock_send_text(state, msg->payload);
    return 0;
}

int
libwebsock_default_control_callback(libwebsock_client_state *state, libwebsock_frame *ctl_frame)
{
    struct evbuffer *output = bufferevent_get_output(state->bev);
    int i;
    unsigned short code;
    unsigned short code_be;
    if (ctl_frame->payload_len > 125) {
        libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
        return 0;
    }
    
    //servify frame
    for (i = 0; i < ctl_frame->payload_len; i++) {
        //this demasks the payload while shifting it 4 bytes to the left.
        *(ctl_frame->rawdata + ctl_frame->payload_offset + i - 4) =
        *(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^ (ctl_frame->mask[i % 4] & 0xff);
    }
    ctl_frame->payload_offset -= 4;
    *(ctl_frame->rawdata + 1) &= 0x7f; //strip mask bit
    switch (ctl_frame->opcode) {
        case WS_OPCODE_CLOSE:  //close frame
            if (!state->close_info && ctl_frame->payload_len >= 2) {
                libwebsock_populate_close_info_from_frame(&state->close_info, ctl_frame);
            }
            if (state->close_info) {
                code = state->close_info->code;
                if ((code >= 0 && code < WS_CLOSE_NORMAL) || code == WS_CLOSE_RESERVED || code == WS_CLOSE_NO_CODE
                    || code == WS_CLOSE_DIRTY || (code > 1011 && code < 3000)) {
                    
                    code_be = htobe16(WS_CLOSE_PROTOCOL_ERROR);
                    memcpy(ctl_frame->rawdata + ctl_frame->payload_offset, &code_be, 2);
                } else if (!validate_utf8_sequence((uint8_t *)state->close_info->reason)) {
                    code_be = htobe16(WS_CLOSE_WRONG_TYPE);
                    memcpy(ctl_frame->rawdata + ctl_frame->payload_offset, &code_be, 2);
                }
            }
            if ((state->flags & STATE_SENT_CLOSE_FRAME) == 0){
                //client request close.  Echo close frame as acknowledgement
                evbuffer_add(output, ctl_frame->rawdata, ctl_frame->payload_offset + ctl_frame->payload_len);
            }
            state->flags |= STATE_SHOULD_CLOSE;
            bufferevent_setcb(state->bev, NULL, libwebsock_handle_send, libwebsock_do_event, (void *) state);
            break;
        case WS_OPCODE_PING:
            *(ctl_frame->rawdata) = 0x8a;
            evbuffer_add(output, ctl_frame->rawdata, ctl_frame->payload_offset + ctl_frame->payload_len);
            break;
        case WS_OPCODE_PONG:
            break;
        default:
            libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
            break;
    }
    return 1;
}
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


void
libwebsock_free_all_frames(libwebsock_client_state *state)
{
    libwebsock_frame *current, *next;
    if (state != NULL) {
        current = state->current_frame;
        if (current) {
            for (; current->prev_frame != NULL; current = current->prev_frame);
            while (current != NULL) {
                next = current->next_frame;
                if (current->rawdata) {
                    free(current->rawdata);
                }
                free(current);
                current = next;
            }
        }
    }
}

void libwebsock_handle_control_frame(libwebsock_client_state *state, libwebsock_frame *ctl_frame) {
    libwebsock_frame *ptr = NULL;
    state->control_callback(state, ctl_frame);
    //the idea here is to reset this frame to the state it was in before we received control frame.
    // Control frames can be injected in the midst of a fragmented message.
    // We need to maintain the link to previous frame if present.
    // It should be noted that ctl_frame is still state->current_frame after this function returns.
    // So even though the below refers to ctl_frame, I'm really setting up state->current_frame to continue receiving data on the next go 'round
    ptr = ctl_frame->prev_frame; //This very well may be a NULL pointer, but just in case we preserve it.
    ctl_frame->prev_frame = ptr;
    //should be able to reuse this frame by setting these two members to zero.  Avoid free/malloc of rawdata
    ctl_frame->state = (WS_FRAME_STATE)0;
    ctl_frame->rawdata_idx = 0;
}

void
libwebsock_cleanup_frames(libwebsock_frame *first)
{
    libwebsock_frame *_this = NULL;
    libwebsock_frame *next = first;
    while (next != NULL) {
        _this = next;
        next = _this->next_frame;
        if (_this->rawdata != NULL) {
            free(_this->rawdata);
        }
        free(_this);
    }
}

inline void
libwebsock_frame_act(libwebsock_client_state *state, libwebsock_frame *frame)
{
    switch (frame->opcode) {
        case WS_OPCODE_CLOSE:
        case WS_OPCODE_PING:
        case WS_OPCODE_PONG:
            libwebsock_handle_control_frame(state, frame);
            break;
        case WS_OPCODE_TEXT:
        case WS_OPCODE_BINARY:
        case WS_OPCODE_CONTINUE:
            libwebsock_dispatch_message(state, frame);
            state->current_frame = NULL;
            break;
        default:
            libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
            break;
    }
}

int libwebsock_read_header(libwebsock_frame *frame) {
    int i;
    enum WS_FRAME_STATE state;
    
    state = frame->state;
    switch (state) {
        case sw_start:
            if (frame->rawdata_idx < 2) {
                break;
            }
            frame->state = sw_got_two;
            break;
        case sw_got_two:
            if ((*(frame->rawdata) & 0x70) != 0) { //some reserved bits were set
                return -1;
            }
            if ((*(frame->rawdata + 1) & 0x80) != 0x80) {
                return -1;
            }
            frame->mask_offset = 2;
            frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
            frame->opcode = *(frame->rawdata) & 0xf;
            frame->payload_len_short = *(frame->rawdata + 1) & 0x7f;
            frame->state = sw_got_short_len;
            break;
        case sw_got_short_len:
            switch (frame->payload_len_short) {
                case 126:
                    if (frame->rawdata_idx < 4) {
                        break;
                    }
                    frame->mask_offset += 2;
                    frame->payload_offset = frame->mask_offset + MASK_LENGTH;
                    frame->payload_len = be16toh(*((unsigned short int *)(frame->rawdata+2)));
                    frame->state = sw_got_full_len;
                    break;
                case 127:
                    if (frame->rawdata_idx < 10) {
                        break;
                    }
                    frame->mask_offset += 8;
                    frame->payload_offset = frame->mask_offset + MASK_LENGTH;
                    frame->payload_len = be64toh(*((unsigned long long *)(frame->rawdata+2)));
                    frame->state = sw_got_full_len;
                    break;
                default:
                    frame->payload_len = frame->payload_len_short;
                    frame->payload_offset = frame->mask_offset + MASK_LENGTH;
                    frame->state = sw_got_full_len;
                    break;
            }
            break;
        case sw_got_full_len:
            if (frame->rawdata_idx < frame->mask_offset + MASK_LENGTH) {
                break;
            }
            for (i = 0; i < MASK_LENGTH; i++) {
                frame->mask[i] = *(frame->rawdata + frame->mask_offset + i) & 0xff;
            }
            frame->state = sw_loaded_mask;
            return 1;
            break;
        case sw_loaded_mask:
            break;
    }
    return 0;
}
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



void libwebsock_handle_accept_ssl(evutil_socket_t listener, short event, void *arg) {
    libwebsock_ssl_event_data *evdata = (libwebsock_ssl_event_data *)arg;
    libwebsock_context *ctx = evdata->ctx;
    SSL_CTX *ssl_ctx = evdata->ssl_ctx;
    libwebsock_client_state *client_state;
    struct bufferevent *bev;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listener, (struct sockaddr *) &ss, &slen);
    if (fd < 0) {
        fprintf(stderr, "Error accepting new connection.\n");
    } else {
        client_state = (libwebsock_client_state *) malloc(sizeof(libwebsock_client_state));
        if (!client_state) {
            fprintf(stderr, "Unable to allocate memory for new connection state structure.\n");
            close(fd);
            return;
        }
        memset(client_state, 0, sizeof(libwebsock_client_state));
        client_state->sockfd = fd;
        client_state->flags |= STATE_CONNECTING | STATE_IS_SSL;
        client_state->control_callback = ctx->control_callback;
        client_state->onopen = ctx->onopen;
        client_state->onmessage = ctx->onmessage;
        client_state->onclose = ctx->onclose;
        client_state->sa = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
        if (!client_state->sa) {
            fprintf(stderr, "Unable to allocate memory for sockaddr_storage.\n");
            free(client_state);
            close(fd);
            return;
        }
        memcpy(client_state->sa, &ss, sizeof(struct sockaddr_storage));
        client_state->ssl = SSL_new(ssl_ctx);
        SSL_set_fd(client_state->ssl, fd);
        if (SSL_accept(client_state->ssl) <= 0) {
            fprintf(stderr, "error during ssl handshake.\n");
        }
        evutil_make_socket_nonblocking(fd);
        bev = bufferevent_openssl_socket_new(ctx->base, -1, client_state->ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE);
        client_state->bev = bev;
        bufferevent_setcb(bev, libwebsock_handshake, NULL, libwebsock_do_event, (void *) client_state);
        bufferevent_setwatermark(bev, EV_READ, 0, 16384);
        bufferevent_enable(bev, EV_READ | EV_WRITE);
    }
}


void
libwebsock_bind_ssl(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile)
{
    libwebsock_bind_ssl_real(ctx, listen_host, port, keyfile, certfile, NULL);
}


void libwebsock_bind_ssl_real(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile,
                              char *chainfile) {
    struct addrinfo hints, *servinfo, *p;
    struct event *listener_event;
    libwebsock_ssl_event_data *evdata;
    int sockfd, yes = 1;
    SSL_CTX *ssl_ctx;
    
    evdata = (libwebsock_ssl_event_data *) malloc(sizeof(libwebsock_ssl_event_data));
    if (!evdata) {
        fprintf(stderr, "Unable to allocate memory for ssl_event_data.\n");
        exit(1);
    }
    memset(evdata, 0, sizeof(libwebsock_ssl_event_data));
    
    if (!ctx->ssl_init) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ctx->ssl_init = 1;
    }
    
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (chainfile != NULL) {
        if (SSL_CTX_load_verify_locations(ssl_ctx, chainfile, NULL) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }
    if (SSL_CTX_use_certificate_file(ssl_ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, keyfile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key.\n");
        exit(1);
    }
    memset(&hints, 0, sizeof(struct addrinfo));
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((getaddrinfo(listen_host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo failed during libwebsock_bind.\n");
        free(ctx);
        exit(-1);
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            free(ctx);
            exit(-1);
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("bind");
            close(sockfd);
            continue;
        }
        break;
    }
    
    if (p == NULL) {
        fprintf(stderr, "Failed to bind to address and port.  Exiting.\n");
        free(ctx);
        exit(-1);
    }
    
    freeaddrinfo(servinfo);
    
    if (listen(sockfd, LISTEN_BACKLOG) == -1) {
        perror("listen");
        exit(-1);
    }
    evdata->ssl_ctx = ssl_ctx;
    evdata->ctx = ctx;
    
    listener_event = event_new(ctx->base, sockfd, EV_READ | EV_PERSIST, libwebsock_handle_accept_ssl, (void *) evdata);
    event_add(listener_event, NULL);
}
/*
 *  sha1.c
 *
 *  Copyright (C) 1998, 2009
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved
 *
 *****************************************************************************
 *  $Id: sha1.c 12 2009-06-22 19:34:25Z paulej $
 *****************************************************************************
 *
 *  Description:
 *      This file implements the Secure Hashing Standard as defined
 *      in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The Secure Hashing Standard, which uses the Secure Hashing
 *      Algorithm (SHA), produces a 160-bit message digest for a
 *      given data stream.  In theory, it is highly improbable that
 *      two messages will produce the same message digest.  Therefore,
 *      this algorithm can serve as a means of providing a "fingerprint"
 *      for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code was
 *      written with the expectation that the processor has at least
 *      a 32-bit machine word size.  If the machine word size is larger,
 *      the code should still function properly.  One caveat to that
 *      is that the input functions taking characters and character
 *      arrays assume that only 8 bits of information are stored in each
 *      character.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long. Although SHA-1 allows a message digest to be generated for
 *      messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is a
 *      multiple of the size of an 8-bit character.
 *
 */


/*
 *  Define the circular shift macro
 */
#define SHA1CircularShift(bits,word) \
((((word) << (bits)) & 0xFFFFFFFF) | \
((word) >> (32-(bits))))

/* Function prototypes */
void SHA1ProcessMessageBlock(SHA1Context *);
void SHA1PadMessage(SHA1Context *);

/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1Reset(SHA1Context *context)
{
    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;
    
    context->Message_Digest[0]      = 0x67452301;
    context->Message_Digest[1]      = 0xEFCDAB89;
    context->Message_Digest[2]      = 0x98BADCFE;
    context->Message_Digest[3]      = 0x10325476;
    context->Message_Digest[4]      = 0xC3D2E1F0;
    
    context->Computed   = 0;
    context->Corrupted  = 0;
}

/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array within the SHA1Context provided
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *
 *  Returns:
 *      1 if successful, 0 if it failed.
 *
 *  Comments:
 *
 */
int SHA1Result(SHA1Context *context)
{
    
    if (context->Corrupted)
    {
        return 0;
    }
    
    if (!context->Computed)
    {
        SHA1PadMessage(context);
        context->Computed = 1;
    }
    
    return 1;
}

/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion of
 *      the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA-1 context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of the
 *          message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1Input(     SHA1Context         *context,
               const unsigned char *message_array,
               unsigned            length)
{
    if (!length)
    {
        return;
    }
    
    if (context->Computed || context->Corrupted)
    {
        context->Corrupted = 1;
        return;
    }
    
    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
        (*message_array & 0xFF);
        
        context->Length_Low += 8;
        /* Force it to 32 bits */
        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            /* Force it to 32 bits */
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }
        
        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }
        
        message_array++;
    }
}

/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      Many of the variable names in the SHAContext, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *
 */
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned K[] =            /* Constants defined in SHA-1   */
    {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int         t;                  /* Loop counter                 */
    unsigned    temp;               /* Temporary word value         */
    unsigned    W[80];              /* Word sequence                */
    unsigned    A, B, C, D, E;      /* Word buffers                 */
    
    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);
    }
    
    for(t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }
    
    A = context->Message_Digest[0];
    B = context->Message_Digest[1];
    C = context->Message_Digest[2];
    D = context->Message_Digest[3];
    E = context->Message_Digest[4];
    
    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
        ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
        ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    context->Message_Digest[0] =
    (context->Message_Digest[0] + A) & 0xFFFFFFFF;
    context->Message_Digest[1] =
    (context->Message_Digest[1] + B) & 0xFFFFFFFF;
    context->Message_Digest[2] =
    (context->Message_Digest[2] + C) & 0xFFFFFFFF;
    context->Message_Digest[3] =
    (context->Message_Digest[3] + D) & 0xFFFFFFFF;
    context->Message_Digest[4] =
    (context->Message_Digest[4] + E) & 0xFFFFFFFF;
    
    context->Message_Block_Index = 0;
}

/*
 *  SHA1PadMessage
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call SHA1ProcessMessageBlock()
 *      appropriately.  When it returns, it can be assumed that the
 *      message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
        
        SHA1ProcessMessageBlock(context);
        
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    
    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;
    
    SHA1ProcessMessageBlock(context);
}
// Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>
// See http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ for details.


#define UTF8_ACCEPT 0
#define UTF8_REJECT 1

static const uint8_t utf8d[] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1f
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3f
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5f
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7f
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9f
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // a0..bf
    8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // c0..df
    0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // e0..ef
    0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // f0..ff
    0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0..s0
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
    1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
    1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
    1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
};

uint32_t inline decode(uint32_t* state, uint32_t* codep, uint32_t byte)
{
    uint32_t type = utf8d[byte];
    
    *codep = (*state != UTF8_ACCEPT) ?
    (byte & 0x3fu) | (*codep << 6) :
    (0xff >> type) & (byte);
    
    *state = utf8d[256 + *state*16 + type];
    return *state;
}



int validate_utf8_sequence(uint8_t *s) {
    uint32_t codepoint;
    uint32_t state = 0;
    
    for(; *s; ++s) {
        decode(&state, &codepoint, *s);
    }
    
    
    return state == UTF8_ACCEPT;
}
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




void
libwebsock_handle_signal(evutil_socket_t sig, short event, void *ptr)
{
    libwebsock_context *ctx = (libwebsock_context *)ptr;
    event_base_loopexit(ctx->base, NULL);
}

void
libwebsock_populate_close_info_from_frame(libwebsock_close_info **info, libwebsock_frame *close_frame)
{
    libwebsock_close_info *new_info;
    unsigned short code_be;
    int at_most;
    
    if (close_frame->payload_len < 2) {
        return;
    }
    
    new_info = (libwebsock_close_info *) malloc(sizeof(libwebsock_close_info));
    if (!new_info) {
        fprintf(stderr, "Error allocating memory for libwebsock_close_info structure.\n");
        return;
    }
    
    memset(new_info, 0, sizeof(libwebsock_close_info));
    memcpy(&code_be, close_frame->rawdata + close_frame->payload_offset, 2);
    at_most = close_frame->payload_len - 2;
    at_most = at_most > 124 ? 124 : at_most;
    new_info->code = be16toh(code_be);
    if (close_frame->payload_len - 2 > 0) {
        memcpy(new_info->reason, close_frame->rawdata + close_frame->payload_offset + 2, at_most);
    }
    *info = new_info;
}

void libwebsock_shutdown(libwebsock_client_state *state) {
    libwebsock_string *str;
    if ((state->flags & STATE_CONNECTED) && state->onclose) {
        state->onclose(state);
    }
    if (state->close_info) {
        free(state->close_info);
    }
    libwebsock_free_all_frames(state);
    if (state->sa) {
        free(state->sa);
    }
    if (state->flags & STATE_CONNECTING) {
        if (state->data) {
            str = (libwebsock_string *)state->data;
            if (str->data) {
                free(str->data);
            }
            free(str);
        }
    }
    
    bufferevent_free(state->bev);
    free(state);
}

void
libwebsock_handle_send(struct bufferevent *bev, void *arg)
{
    libwebsock_client_state *state = (libwebsock_client_state *)arg;
    
    if (state->flags & STATE_SHOULD_CLOSE) {
        libwebsock_shutdown(state);
    }
    
}

void
libwebsock_send_cleanup(const void *data, size_t len, void *arg)
{
    free((void *) data);
}

int
libwebsock_send_fragment(libwebsock_client_state *state, const char *data, unsigned long long len, int flags)
{
    struct evbuffer *output = bufferevent_get_output(state->bev);
    unsigned long long payload_len_long_be;
    unsigned short int payload_len_short_be;
    unsigned char finNopcode, payload_len_small;
    unsigned int payload_offset = 2;
    unsigned int frame_size;
    char *frame;
    
    finNopcode = flags & 0xff;
    if (len <= 125) {
        frame_size = 2 + len;
        payload_len_small = len & 0xff;
    } else if (len > 125 && len <= 0xffff) {
        frame_size = 4 + len;
        payload_len_small = 126;
        payload_offset += 2;
    } else if (len > 0xffff && len <= 0xffffffffffffffffLL) {
        frame_size = 10 + len;
        payload_len_small = 127;
        payload_offset += 8;
    } else {
        fprintf(stderr, "Whoa man.  What are you trying to send?\n");
        return -1;
    }
    frame = (char *) malloc(frame_size);
    memset(frame, 0, frame_size);
    payload_len_small &= 0x7f;
    *frame = finNopcode;
    *(frame + 1) = payload_len_small;
    if (payload_len_small == 126) {
        len &= 0xffff;
        payload_len_short_be = htobe16(len);
        memcpy(frame + 2, &payload_len_short_be, 2);
    }
    if (payload_len_small == 127) {
        payload_len_long_be = htobe64(len);
        memcpy(frame + 2, &payload_len_long_be, 8);
    }
    memcpy(frame + payload_offset, data, len);
    
    return evbuffer_add_reference(output, frame, frame_size, libwebsock_send_cleanup, NULL);
}

void
libwebsock_handle_accept(evutil_socket_t listener, short event, void *arg)
{
    libwebsock_context *ctx = (libwebsock_context *)arg;
    libwebsock_client_state *client_state;
    struct bufferevent *bev;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listener, (struct sockaddr *) &ss, &slen);
    if (fd < 0) {
        fprintf(stderr, "Error accepting new connection.\n");
    } else {
        client_state = (libwebsock_client_state *) malloc(sizeof(libwebsock_client_state));
        if (!client_state) {
            fprintf(stderr, "Unable to allocate memory for new connection state structure.\n");
            close(fd);
            return;
        }
        memset(client_state, 0, sizeof(libwebsock_client_state));
        client_state->sockfd = fd;
        client_state->flags |= STATE_CONNECTING;
        client_state->control_callback = ctx->control_callback;
        client_state->onopen = ctx->onopen;
        client_state->onmessage = ctx->onmessage;
        client_state->onclose = ctx->onclose;
        client_state->sa = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
        if (!client_state->sa) {
            fprintf(stderr, "Unable to allocate memory for sockaddr_storage.\n");
            free(client_state);
            close(fd);
            return;
        }
        memcpy(client_state->sa, &ss, sizeof(struct sockaddr_storage));
        evutil_make_socket_nonblocking(fd);
        bev = bufferevent_socket_new(ctx->base, fd, BEV_OPT_CLOSE_ON_FREE);
        client_state->bev = bev;
        bufferevent_setcb(bev, libwebsock_handshake, libwebsock_handle_send, libwebsock_do_event, (void *) client_state);
        bufferevent_setwatermark(bev, EV_READ, 0, 16384);
        bufferevent_enable(bev, EV_READ | EV_WRITE);
    }
}

void libwebsock_do_event(struct bufferevent *bev, short event, void *ptr) {
    libwebsock_client_state *state = (libwebsock_client_state *)ptr;
    
    if (event & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        libwebsock_shutdown(state);
    }
}

void libwebsock_handle_recv(struct bufferevent *bev, void *ptr) {
    //alright... while we haven't reached the end of data keep trying to build frames
    //possible states right now:
    // 1.) we're receiving the beginning of a new frame
    // 2.) we're receiving more data from a frame that was created previously and was not complete
    libwebsock_client_state *state = (libwebsock_client_state *)ptr;
    libwebsock_frame *current = NULL, *_new = NULL;
    struct evbuffer *input;
    int i, datalen, err;
    char buf[1024];
    
    input = bufferevent_get_input(bev);
    while (evbuffer_get_length(input)) {
        datalen = evbuffer_remove(input, buf, sizeof(buf));
        for (i = 0; i < datalen; i++) {
            if (state->current_frame == NULL) {
                state->current_frame = (libwebsock_frame *) malloc(sizeof(libwebsock_frame));
                memset(state->current_frame, 0, sizeof(libwebsock_frame));
                state->current_frame->payload_len = -1;
                state->current_frame->rawdata_sz = FRAME_CHUNK_LENGTH;
                state->current_frame->rawdata = (char *) malloc(state->current_frame->rawdata_sz);
            }
            current = state->current_frame;
            if (current->rawdata_idx >= current->rawdata_sz) {
                current->rawdata_sz += current->rawdata_sz;
                current->rawdata = (char *) realloc(current->rawdata, current->rawdata_sz);
            }
            *(current->rawdata + current->rawdata_idx++) = buf[i];
            if (current->state != sw_loaded_mask) {
                err = libwebsock_read_header(current);
                if (err == -1) {
                    libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
                }
                if (err == 0) {
                    continue;
                }
            }
            
            if (current->rawdata_idx < current->payload_offset + current->payload_len) {
                continue;
            }
            
            if (state->flags & STATE_RECEIVING_FRAGMENT) {
                if (current->fin == 1) {
                    if ((current->opcode & 0x8) == 0) {
                        if (current->opcode) { //non-ctrl and has opcode in the middle of fragment.  FAIL
                            libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
                            break;
                        }
                        state->flags &= ~STATE_RECEIVING_FRAGMENT;
                    }
                    libwebsock_frame_act(state, current);
                } else {
                    //middle of fragment non-fin frame
                    if (current->opcode) { //cannot have opcode
                        libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
                        break;
                    }
                    _new = (libwebsock_frame *) malloc(sizeof(libwebsock_frame));
                    memset(_new, 0, sizeof(libwebsock_frame));
                    _new->rawdata_sz = FRAME_CHUNK_LENGTH;
                    _new->rawdata = (char *) malloc(_new->rawdata_sz);
                    _new->prev_frame = current;
                    current->next_frame = _new;
                    state->current_frame = _new;
                }
            } else {
                if (current->fin == 1) {
                    //first frame and FIN, handle normally.
                    if (!current->opcode) { //must have opcode, cannot be continuation frame.
                        libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
                        break;
                    }
                    libwebsock_frame_act(state, current);
                } else {
                    //_new fragment series beginning
                    if (current->opcode & 0x8) { //can't fragment control frames.  FAIL
                        libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
                        break;
                    }
                    if (!current->opcode) { //_new fragment series must have opcode.
                        libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
                        break;
                    }
                    _new = (libwebsock_frame *) malloc(sizeof(libwebsock_frame));
                    memset(_new, 0, sizeof(libwebsock_frame));
                    _new->rawdata_sz = FRAME_CHUNK_LENGTH;
                    _new->rawdata = (char *) malloc(_new->rawdata_sz);
                    _new->prev_frame = current;
                    current->next_frame = _new;
                    state->current_frame = _new;
                    state->flags |= STATE_RECEIVING_FRAGMENT;
                }
            }
            if (state->flags & STATE_SHOULD_CLOSE) { //after each complete frame, check to see if we should stop processing now.
                break;
            }
        }
    }
}

void
libwebsock_fail_connection(libwebsock_client_state *state, unsigned short close_code)
{
    struct evbuffer *output = bufferevent_get_output(state->bev);
    char close_frame[4] = { (char)0x88, (char)0x02, (char)0x00, (char)0x00 };
    unsigned short code_be = htobe16(close_code);
    memcpy(&close_frame[2], &code_be, 2);
    
    evbuffer_add(output, close_frame, 4);
    state->flags |= STATE_SHOULD_CLOSE;
}

void
libwebsock_dispatch_message(libwebsock_client_state *state, libwebsock_frame *current)
{
    unsigned long long message_payload_len, message_offset;
    int message_opcode;
    unsigned int i;
    char *message_payload;
    
    libwebsock_frame *first = NULL;
    libwebsock_message *msg = NULL;
    if (current == NULL) {
        fprintf(stderr, "Somehow, null pointer passed to libwebsock_dispatch_message.\n");
        exit(1);
    }
    message_offset = 0;
    message_payload_len = 0;
    for (; current->prev_frame != NULL; current = current->prev_frame) {
        message_payload_len += current->payload_len;
    }
    message_payload_len += current->payload_len;
    first = current;
    message_opcode = current->opcode;
    message_payload = (char *) malloc(message_payload_len + 1);
    
    for (; current != NULL; current = current->next_frame) {
        for (i = 0; i < current->payload_len; i++) {
            *(message_payload + message_offset++) =
            *(current->rawdata + current->payload_offset + i) ^ (current->mask[i % 4] & 0xff);
        }
    }
    
    *(message_payload + message_offset) = '\0';
    
    libwebsock_cleanup_frames(first);
    
    if(message_opcode == WS_OPCODE_TEXT) {
        if(!validate_utf8_sequence((uint8_t *)message_payload)) {
            fprintf(stderr, "Error validating UTF-8 sequence.\n");
            free(message_payload);
            libwebsock_fail_connection(state, WS_CLOSE_WRONG_TYPE);
            return;
        }
    }
    
    msg = (libwebsock_message *) malloc(sizeof(libwebsock_message));
    memset(msg, 0, sizeof(libwebsock_message));
    msg->opcode = message_opcode;
    msg->payload_len = message_payload_len;
    msg->payload = message_payload;
    if (state->onmessage != NULL) {
        state->onmessage(state, msg);
    } else {
        fprintf(stderr, "No onmessage call back registered with libwebsock.\n");
    }
    free(msg->payload);
    free(msg);
}

void libwebsock_handshake_finish(struct bufferevent *bev, libwebsock_client_state *state) {
    //TODO: this is shite.  Clean it up.
    libwebsock_string *str = (libwebsock_string *)state->data;
    struct evbuffer *output;
    char buf[1024];
    char sha1buf[45];
    char concat[1024];
    unsigned char sha1mac[20];
    char *tok = NULL, *headers = NULL, *key = NULL;
    char *base64buf = NULL;
    const char *GID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    SHA1Context shactx;
    SHA1Reset(&shactx);
    unsigned int n = 0;
    
    output = bufferevent_get_output(bev);
    
    headers = (char *) malloc(str->data_sz + 1);
    if (!headers) {
        fprintf(stderr, "Unable to allocate memory in libwebsock_handshake..\n");
        bufferevent_free(bev);
        return;
    }
    memset(headers, 0, str->data_sz + 1);
    strncpy(headers, str->data, str->idx);
    for (tok = strtok(headers, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")) {
        if (strstr(tok, "Sec-WebSocket-Key: ") != NULL) {
            key = (char *) malloc(strlen(tok));
            strncpy(key, tok + strlen("Sec-WebSocket-Key: "), strlen(tok));
            break;
        }
    }
    free(headers);
    free(str->data);
    free(str);
    state->data = NULL;
    
    if (key == NULL) {
        fprintf(stderr, "Unable to find key in request headers.\n");
        bufferevent_free(bev);
        return;
    }
    
    memset(concat, 0, sizeof(concat));
    strncat(concat, key, strlen(key));
    strncat(concat, GID, strlen(GID));
    SHA1Input(&shactx, (unsigned char *) concat, strlen(concat));
    SHA1Result(&shactx);
    free(key);
    key = NULL;
    sprintf(sha1buf, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0], shactx.Message_Digest[1], shactx.Message_Digest[2], shactx.Message_Digest[3], shactx.Message_Digest[4]);
    for (n = 0; n < (strlen(sha1buf) / 2); n++) {
        sscanf(sha1buf + (n * 2), "%02hhx", sha1mac + n);
    }
    base64buf = (char *) malloc(256);
    base64_encode(sha1mac, 20, base64buf, 256);
    memset(buf, 0, 1024);
    snprintf(buf, 1024,
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Server: %s/%s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n", PACKAGE_NAME, PACKAGE_VERSION, base64buf);
    free(base64buf);
    
    evbuffer_add(output, buf, strlen(buf));
    bufferevent_setcb(bev, libwebsock_handle_recv, libwebsock_handle_send, libwebsock_do_event, (void *) state);
    
    state->flags &= ~STATE_CONNECTING;
    state->flags |= STATE_CONNECTED;
    
    if (state->onopen != NULL) {
        state->onopen(state);
    }
}

void libwebsock_handshake(struct bufferevent *bev, void *ptr) {
    //TODO: this is shite too.
    libwebsock_client_state *state = (libwebsock_client_state *)ptr;
    libwebsock_string *str = NULL;
    struct evbuffer *input;
    char buf[1024];
    int datalen;
    input = bufferevent_get_input(bev);
    str = (libwebsock_string *)state->data;
    if (!str) {
        state->data = (libwebsock_string *) malloc(sizeof(libwebsock_string));
        if (!state->data) {
            fprintf(stderr, "Unable to allocate memory in libwebsock_handshake.\n");
            bufferevent_free(bev);
            return;
        }
        str = (libwebsock_string *)state->data;
        memset(str, 0, sizeof(libwebsock_string));
        str->data_sz = FRAME_CHUNK_LENGTH;
        str->data = (char *) malloc(str->data_sz);
        if (!str->data) {
            fprintf(stderr, "Unable to allocate memory in libwebsock_handshake.\n");
            bufferevent_free(bev);
            return;
        }
        memset(str->data, 0, str->data_sz);
    }
    
    while (evbuffer_get_length(input)) {
        datalen = evbuffer_remove(input, buf, sizeof(buf));
        
        if (str->idx + datalen >= str->data_sz) {
            str->data = (char *)realloc(str->data, str->data_sz * 2 + datalen);
            if (!str->data) {
                fprintf(stderr, "Failed realloc.\n");
                bufferevent_free(bev);
                return;
            }
            str->data_sz += str->data_sz + datalen;
            memset(str->data + str->idx, 0, str->data_sz - str->idx);
        }
        memcpy(str->data + str->idx, buf, datalen);
        str->idx += datalen;
        
        if (strstr(str->data, "\r\n\r\n") != NULL || strstr(str->data, "\n\n") != NULL) {
            libwebsock_handshake_finish(bev, state);
        }
    }
}


