//
//  Router.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 28.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "Router.h"
#include "Server.h"

Router *Router::inst = 0;

Router *Router::instance() {
    if(!inst)
        inst = new Router();
    
    return inst;
}

void Router::start(unsigned int port) {
    this->port = port;
    /* ADD SOME SERVERS */
    
    /*
    char *servers[2];
    servers[0] = "94.229.35.144";
    servers[1] = "192.168.0.100";
    
    for(int i=0; i < 2; i++) {
        connection *conn = new connection;
        struct sockaddr_in *sin = new struct sockaddr_in;
        node *n = new node;
        
        conn->bev = NULL;
        memset(sin, 0, sizeof(struct sockaddr_in));
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        inet_pton(AF_INET, servers[i], &sin->sin_addr);
        conn->sin = sin;
        n->conn = conn;
        n->status = DISCONNECT;
        n->failed = 0;
        
        //nodes.push_back(n);
    }
    */
    
    pthread_create(this->getThread(), NULL, Router::start, (void *)Manager::instance());
}

void *Router::start(void *ptr) {
    Manager *m = (Manager *)ptr;
    
    int sock;
    event *ev_accept;
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("0.0.0.0"); // INADDR_ANY;
    server_addr.sin_port = htons(m->getRouter()->getPort());
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(sock < 0) {
        printf("ERROR opening socket\n");
        exit(1);
    }
    
    if(bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        printf("ERROR binding socket\n");
        exit(1);
    }
    
    if(listen(sock, 5) < 0) {
        perror("ERROR listening");
        exit(1);
    }
    
    log(stderr, "[DEBUG] ROUTER start listening\n");
    
    if(evthread_use_pthreads() < 0) {
        perror("failed start event thread");
        exit(1);
    }
    
    event_base *base = event_base_new();
    evutil_make_socket_nonblocking(sock);
    
    int yes = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        perror("setsockopt");

    ev_accept = event_new(base, sock, EV_READ|EV_PERSIST, Router::acceptCallback, (void *)ptr);
    
    event_add(ev_accept, NULL);
    
    m->getRouter()->setBase(base);
    
    event_base_dispatch(base);
    event_base_free(base);
    base = NULL;
    
    /* FREE */
    
    close(sock);
    
    return  NULL;
}

void Router::acceptCallback(int fd, short ev, void *arg) {
    int client_sock;
    
    Manager *m = (Manager *)arg;
    Router *r = m->getRouter();
    
    struct sockaddr_in client_addr;
    socklen_t client_length = sizeof(client_addr);
    
    client_sock = accept(fd, (sockaddr *)&client_addr, &client_length);
    if(client_sock < 0) {
        perror("client accept");
        return;
    }
    
    if(evutil_make_socket_nonblocking(client_sock) < 0) {
        perror("client non-block");
        close(client_sock);
        return;
    }
    
    LISTNODE::iterator it;
    
    node *n = NULL;
    
    /////////////////////////////////////////////////////
    DMLOCK(r->getServer()->getNodeMutex());
        char addr1[INET_ADDRSTRLEN];
        char addr2[INET_ADDRSTRLEN];
    
        inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, addr2, INET_ADDRSTRLEN);
    
    
        for(it = r->getServer()->nodes.begin(); it != r->getServer()->nodes.end(); it++) {
            n = *it;
            
            inet_ntop(AF_INET, &n->conn->sin->sin_addr.s_addr, addr1, INET_ADDRSTRLEN);
            
            log(stderr, "[DEBUG] ADDR CMP: %s %s %d/%d\n",addr1,addr2,strcmp(addr1, addr2) == 0, memcmp(&n->conn->sin->sin_addr.s_addr, &client_addr.sin_addr.s_addr, sizeof(struct in_addr)) == 0);
            
            //if(strcmp(addr1, addr2) == 0)
            if(memcmp(&n->conn->sin->sin_addr.s_addr, &client_addr.sin_addr.s_addr, sizeof(struct in_addr)) == 0)
                break;
            else
                n = NULL;
        }
        
        if(n == NULL) {
            log(stderr, "[DEBUG] save new server\n");
            // WE DONT FIND SERVER, WE SAVE HIM
            
            n = new node;
            struct sockaddr_in *sin = new struct sockaddr_in;
            memcpy(sin, &client_addr, sizeof(struct sockaddr_in));
            n->create(NULL, sin);
            sin->sin_port = htons(r->getPort());
            
            r->getServer()->nodes.push_back(n);
        } else {
            log(stderr, "[DEBUG] ZHODA\n");
            
            if(n->status == DISCONNECT) {
                n->status = CONNECT;
                n->failed = 0;
            } else {
                /* TODO */
                // UZ MA VYTVORENE SPOJENIE ALEBO SA PRAVE PRIPAJA
            }
        }
    
        nodeInfo *inf = new nodeInfo;
        inf->s = r->getServer();
        inf->n = n;
        inf->buffer_length = 0;
    
    
        evutil_make_socket_nonblocking(client_sock);
        n->conn->bev = bufferevent_socket_new(r->getBase(), client_sock, BEV_OPT_CLOSE_ON_FREE);

        //log(stderr, "[DEBUG] ROUTER CONNECT BEV: %lld\n", n->conn->bev);
    
    bufferevent_setcb(n->conn->bev, /*Router::readCallback*/ node::readcb, Router::writeCallback, Router::eventCallback, (void *)inf);

        bufferevent_enable(n->conn->bev, EV_READ | EV_WRITE);
    /////////////////////////////////////////////////////
    DMUNLOCK(r->getServer()->getNodeMutex());
}
/*
void Router::readCallback(struct bufferevent *bev, void *ptr) {
    nodeInfo *inf = (nodeInfo *)ptr;
    //node *n = inf->n;
    //Server *s = inf->s;
    
    dataList *l = NULL;
    
    packetHeader *ph;
    if(inf->buffer.empty())
        ph = NULL;
    else {
        // LOAD PACKET HEADER
        l = inf->buffer.front();
        if(l->length < sizeof(packetHeader)) {
            log(stderr, "[DEBUG] nekompletna hlavicka v prvom pakete\n");
            Router::shutdown(inf);
            return;
        }
        ph = new packetHeader;
        memcpy(ph, l->data, sizeof(packetHeader));
    }
    
    unsigned long long length = 0;
    char buffer[ROUTER_BUFFER];
    
    struct evbuffer *input = bufferevent_get_input(bev);
    
    while (evbuffer_get_length(input) != 0) {
        length = evbuffer_remove(input, buffer, ROUTER_BUFFER);
        log(stderr, "[DEBUG] length: %lld / %d\n", length, inf->buffer_length);
        inf->buffer_length += length;
        
        if(ph == NULL && length < sizeof(packetHeader)) {
            // PRVA CAST MUSI MAT VELKOST ASPON HLAVICKY
            log(stderr,"[DEBUG] too short packet, without header ???\n");
            Router::shutdown(inf);
            return;
        } else if(ph == NULL) {
            ph = new packetHeader;
            memcpy(ph, buffer, sizeof(packetHeader));
            
            log(stderr, "[DEBUG] packet length: %u\n", ph->length);
        }
        
        if(length < 0) {
            log(stderr,"[DEBUG] evbuffer_remove < 0\n");
            Router::shutdown(inf);
            
            if(ph != NULL)
                delete ph;
            return;
        }
        
        dataList *tmp = new dataList;
        tmp->data = new char[length];
        memcpy(tmp->data, buffer, length);
        tmp->length = length;
        
        if(length < ROUTER_BUFFER) {
            log(stderr,"[DEBUG] mensie, asi koniec paketu ?\n");
            
            int estimate = inf->buffer_length - (ph->length + sizeof(packetHeader));
            if(estimate < 0) { // ESTE NIE JE NACITANY CELY PAKET
                inf->buffer.push(tmp);
                log(stderr,"[DEBUG] pokracujem v citani paketu\n");
                continue;
            } else {
                char *buff = NULL;
                dataList *ltmp = NULL;
                char *tmpbuf = NULL;
                
                if(estimate > 0) {
                    // MAME VIACEJ DAT AKO POTREBUJEME
                    tmpbuf = tmp->data;
                    tmp->data = new char[length - estimate];
                    tmp->length = length - estimate;
                    
                }
                
                buff = new char[ph->length + sizeof(packetHeader)];
                
                int lentmp = 0;
                // COPY TO BUFFER
                while(inf->buffer.empty() == false) {
                    ltmp = inf->buffer.front();
                    memcpy(buff+lentmp, ltmp->data, ltmp->length);
                    lentmp += ltmp->length;
                    inf->buffer.pop();
                    
                    delete ltmp;
                }
                // PRIDAME POSLEDNU CAST
                memcpy(buff+lentmp, tmp->data, tmp->length);
                
                Packet *p = new Packet;
                p->setLocalDelivery(); // FROM REMOTE RESOURCE
                
                if(p->parsePacket(buff, inf->buffer_length) == false) {
                    log(stderr,"[DEBUG] paket nie je validny\n");
                    Router::shutdown(inf);
                    
                    if(ph != NULL)
                        delete ph;
                    
                    delete p;
                    return;
                }
                
                if(ph != NULL) {
                    delete ph;
                    ph = NULL;
                }
                
                inf->buffer_length = 0;
                inf->s->insertPacket(p);

                char *delbuf = tmpbuf;
                while(tmpbuf != NULL) {
                    ph = new packetHeader;
                    memcpy(ph, buffer, sizeof(packetHeader));
                    
                    if(estimate >= (ph->length + sizeof(packetHeader))) {
                        buff = new char[ph->length + sizeof(packetHeader)];
                        memcpy(buff, tmpbuf, ph->length + sizeof(packetHeader));
                        
                        Packet *p = new Packet;
                        p->setLocalDelivery(); // FROM REMOTE RESOURCE
                        
                        if(p->parsePacket(buff, ph->length + sizeof(packetHeader)) == false) {
                            log(stderr,"[DEBUG] paket nie je validny\n");
                            Router::shutdown(inf);
                            
                            if(ph != NULL)
                                delete ph;
                            
                            delete delbuf;
                            
                            delete p;
                            return;
                        }
                        
                        if(ph != NULL) {
                            delete ph;
                            ph = NULL;
                        }
                        
                        inf->s->insertPacket(p);
                        estimate -= ph->length + sizeof(packetHeader);
                        tmpbuf += ph->length + sizeof(packetHeader);
                    } else {
                        
                    }
                }
                if(delbuf != NULL)
                    delete delbuf;
            }
        } else
            inf->buffer.push(tmp);
    }
}
*/

void Router::writeCallback(struct bufferevent *bev, void *arg) {
    log(stderr,"[DEBUG] write callback\n");
    /*
    if (state->flags & STATE_SHOULD_CLOSE) {
        libwebsock_shutdown(state);
    }
    */
}


void Router::eventCallback(struct bufferevent *bev, short event, void *ptr) {
    log(stderr,"[DEBUG] event callback\n");
    if (event & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        // FREE AND CLOSE CONNECTION
        Router::shutdown((nodeInfo *)ptr);
    }
}

void Router::shutdown(nodeInfo *inf) {
    node *n = inf->n;
    
    log(stderr,"[DEBUG] ROUTER::shutdown\n");

    while(inf->buffer.empty() == false) {
        dataList *l = inf->buffer.front();
        delete l;
        
        inf->buffer.pop();
    }
    delete inf;

    if (n->status != DISCONNECT) {
        MLOCK(&n->mutex);
        n->status = DISCONNECT;
        n->failed = 0;
        MUNLOCK(&n->mutex);
    }
    
    bufferevent_free(n->conn->bev);
    n->conn->bev = NULL;
}
