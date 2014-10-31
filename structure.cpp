//
//  structure.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 29.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "structure.h"
#include "Server.h"
#include "DatabasePacket.h"
#include "Node.h"

#include <arpa/inet.h>
#include <resolv.h>

bool node::connect(event_base * base) {
    ///////////////////////////////////
    DMLOCK(&this->mutex);
    
    // CHECK IF CONNECTING OR CONNECTED
    if(this->status != DISCONNECT) {
        ///////////////////////////////////
        DMUNLOCK(&this->mutex);
        return true;
    }
    
    nodeInfo *inf = new nodeInfo;
    inf->buffer_length = 0;
    inf->n = this;
    inf->s = Manager::instance()->getServer();
    
    conn->bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
    bufferevent_setcb(conn->bev, node::readcb, NULL, node::eventcb, (void *)inf);
    if(bufferevent_socket_connect(conn->bev, (struct sockaddr *)(conn->sin),sizeof(struct sockaddr_in)) < 0) {
        bufferevent_free(this->conn->bev);
        this->conn->bev = NULL;
        this->failed++;
        
        delete inf;
        
        ///////////////////////////////////
        DMUNLOCK(&this->mutex);
        return false;
    }
    
    bufferevent_enable(this->conn->bev, EV_READ|EV_WRITE);
    
    this->status = CONNECTING;
    ///////////////////////////////////
    DMUNLOCK(&this->mutex);
    return true;
}

bool node::sendPacket(Packet *p) {
    if(status == CONNECT) {
        struct evbuffer *buf = bufferevent_get_output(conn->bev);
        
        if(evbuffer_add(buf, p->getFullPacket(), p->getFullLength()) != 0) {
            // CHYBA PRI POSIELANI :(
            log(stderr,"[DEBUG] evbuffer_add error\n");
        }
        log(stderr,"[DEBUG] packet send\n");
        return true;
    } else
        return false;
}

void node::eventcb(struct bufferevent *bev, short events, void *ptr) {
    nodeInfo *inf = (nodeInfo *)ptr;
    node *n = inf->n;
    
    if (events & BEV_EVENT_CONNECTED) {
        printf("EVENT NODE CONN\n");
        
        n->status = CONNECT;
    } else if (events & BEV_EVENT_ERROR) {
        printf("EVENT NODE ERROR\n");
        n->status = DISCONNECT;
        n->conn->bev = NULL;
        n->failed++;
    }
    printf("EVENT NODE\n");
    
}

void node::readcb(struct bufferevent *bev, void *ptr) {
    nodeInfo *inf = (nodeInfo *)ptr;
    node *n = inf->n;
    //Node *ss = inf->sn;
    
    dataList *l = NULL;
    packetHeader *ph = NULL;
    
    unsigned long long length = 0;
    char buffer[ROUTER_BUFFER];
    
    struct evbuffer *input = bufferevent_get_input(bev);
    while(true) {
        // FIRST LOAD PACKET HEADER
        if(inf->buffer.empty()) {
            if(evbuffer_get_length(input) < sizeof(packetHeader)) {
                break;
            } else {
                length = evbuffer_copyout(input, buffer, sizeof(packetHeader));
                if(length != sizeof(packetHeader))
                    break;
                
                ph = new packetHeader;
                memcpy(ph, buffer, sizeof(packetHeader));
                
                // REMOVE DATA FROM QUEUE IN EVBUFFER
                evbuffer_drain(input, sizeof(packetHeader));
                
                if(evbuffer_get_length(input) < ph->length) {
                    dataList *tmp = new dataList;
                    tmp->data = new char[length];
                    memcpy(tmp->data, buffer, length);
                    
                    // ADD DATA TO QUEUE
                    inf->buffer.push(tmp);
                    break;
                }
            }
        } else {
            // LOAD PACKET HEADER
            l = inf->buffer.front();
            
            ph = new packetHeader;
            memcpy(ph, l->data, sizeof(packetHeader));
        }
        
        if(evbuffer_get_length(input) >= ph->length) {
            unsigned long long packetSize = ph->length + sizeof(packetHeader);
            unsigned char *data = new unsigned char[ph->length + sizeof(packetHeader)];
            
            // COPY PACKET HEADER
            memcpy(data, ph, sizeof(packetHeader));
            
            // PREPARE PACKET DATA
            length = evbuffer_copyout(input, data+sizeof(packetHeader), ph->length);
            
            if(length != ph->length)
                break;
            
            // REMOVE DATA FROM EVBUFFER
            evbuffer_drain(input, ph->length);
            
            // CREATE PACKET
            Packet *p = new Packet;
            
            // SET SOURCE FROM NODE
            p->setNode(n);
            
            // SET LOCAL DELIVERY
            p->setLocalDelivery();
            
            // PARSE PACKET
            if(p->parsePacket((char *)data, packetSize) == false) {
                log(stderr,"[DEBUG] paket nie je validny\n");
                Node::shutdown(inf);
                
                delete p;
                break;
            }
            
            // ADD PACKET TO QUEUE
            DatabasePacket::instance()->add(p);
            
            delete ph;
            ph = NULL;
        } else
            break;
    }
    
    if(ph != NULL)
        delete ph;
    
    //Router::readCallback(bev, ptr);
}






void debugPacket(packet *p) {
    printf("[DEBUG] Type: %d\n", p->header.type);
    printf("[DEBUG] Length: %lld\n", p->header.length);
    
    printf("[DEBUG] D: ");
    for(int i=0;i<sizeof(key);i++)
        printf("%#02x ", p->header.destination.data[i]);
    printf("\n");
    
    printf("[DEBUG] S: ");
    for(int i=0;i<sizeof(key);i++)
        printf("%#02x ", p->header.source.data[i]);
    printf("\n");
    
    printf("[DEBUG] Data: ");
    for(int i=0;i<p->header.length;i++)
        printf("%02x ", p->data[i]);
    printf("\n");
}










char **getTXT(const char *name, int *size) {
    unsigned char response[NS_PACKETSZ];  /* big enough, right? */
    ns_msg handle;
    ns_rr rr;
    int ns_index, len;
    char dispbuf[4096];
    
    if ((len = res_search(name, ns_c_in, ns_t_txt, response, sizeof(response))) < 0)
        return (char **)NULL;
    
    if (ns_initparse(response, len, &handle) < 0)
        return 0;
    
    if((len = ns_msg_count(handle, ns_s_an)) < 0)
        return 0;
    
    char **out = (char **)new char*[len];
    
    for (ns_index = 0; ns_index < len; ns_index++) {
        out[ns_index] = NULL;
        
        if (ns_parserr(&handle, ns_s_an, ns_index, &rr))
            continue;
        
        ns_sprintrr (&handle, &rr, NULL, NULL, dispbuf, sizeof (dispbuf));
        if (ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_txt) {
            //char mxname[NS_MAXDNAME];
            /*
             dn_expand(
             ns_msg_base(handle),
             ns_msg_base(handle) + ns_msg_size(handle),
             ns_rr_rdata(rr) + NS_INT16SZ,
             mxname,
             sizeof(mxname)
             );
             */
            
            
            
            out[ns_index] = new char[ns_rr_rdlen(rr)];
            memcpy(out[ns_index],ns_rr_rdata(rr) + NS_INT8SZ, ns_rr_rdlen(rr)-1);
            out[ns_index][ns_rr_rdlen(rr)-1] = '\0';
            
            //mxs[mx_index++] = strdup(mxname);
        }
    }
    
    *size = len;
    
    return out;
}

/*
 int size;
 char **list = getTXT("srv.crycom.net", &size);
 
 printf("%d\n",size);
 for(int i=0;i < size;i++)
 printf("%s\n", list[i]);
 
 return 0;
 */