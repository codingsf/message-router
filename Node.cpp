//
//  Node.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 12.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "Node.h"

Node *Node::inst = 0;

Node *Node::instance() {
    if(!inst)
        inst = new Node();
    return inst;
}

void Node::start(unsigned int port) {
    setPort(port);
    
    pthread_create(this->getThread(), NULL, Node::start, (void *)this);
}

void *Node::start(void *ptr) {
    Node *n = (Node *)ptr;
 
    int sock;
    event *ev_accept;
    struct sockaddr_in server_addr;
    
    memset(&server_addr, 0, sizeof(server_addr));
    
    server_addr.sin_family = AF_INET;
    
#ifdef _DEBUG_
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // INADDR_ANY;
#else
    server_addr.sin_addr.s_addr = inet_addr("0.0.0.0"); // INADDR_ANY;
#endif
    
    server_addr.sin_port = htons(n->getPort());
    
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
    
    log(stderr, "[DEBUG] SNODE start listening\n");
    
    if(evthread_use_pthreads() < 0) {
        perror("failed start event thread");
        exit(1);
    }
    
    event_base *base = event_base_new();
    evutil_make_socket_nonblocking(sock);
    
    int yes = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        perror("setsockopt");
    
    ev_accept = event_new(base, sock, EV_READ|EV_PERSIST, Node::acceptCallback, (void *)ptr);
    
    event_add(ev_accept, NULL);
    
    n->setBase(base);
    
    event_base_dispatch(base);
    event_base_free(base);
    base = NULL;
    
    /* FREE */
    
    close(sock);
    
    return NULL;
}


void Node::acceptCallback(int fd, short ev, void *arg) {
    int client_sock;
    
    Node *sn = (Node *)arg;
    
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
    
    std::stringstream ss;
    std::string s;
    
    char addr[INET_ADDRSTRLEN];
    
    // PARSE IP ADDRESS
    inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, addr, INET_ADDRSTRLEN);
    ss << addr;
    ss >> s;
    
    // CREATE NODE STRUCTURE
    node *n = new node;
    struct sockaddr_in *sin = new struct sockaddr_in;
    memcpy(sin, &client_addr, sizeof(struct sockaddr_in));
    sin->sin_port = htons(ROUTER_PORT);
    n->create(NULL, sin);
    
    // SAVE HANDLER
    DatabaseNode *dn = DatabaseNode::instance();
    dn->queueAdd(s, n);

    // CREATE HELPER STRUCTURE
    nodeInfo *inf = new nodeInfo;
    inf->sn = sn;
    inf->n = n;
    inf->buffer_length = 0;
    
    
    evutil_make_socket_nonblocking(client_sock);
    n->conn->bev = bufferevent_socket_new(sn->getBase(), client_sock, BEV_OPT_CLOSE_ON_FREE);
    
    bufferevent_setcb(n->conn->bev, /*Node::readCallback*/ node::readcb, Node::writeCallback, Node::eventCallback, (void *)inf);
    
    bufferevent_enable(n->conn->bev, EV_READ | EV_WRITE);
    
    n->status = CONNECT;
}
/*
void Node::readCallback(struct bufferevent *bev, void *ptr) {
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
}
*/
/*
    // TU BUDE KONIEC

    while (evbuffer_get_length(input) != 0) {
        length = evbuffer_remove(input, buffer, ROUTER_BUFFER);
        
        log(stderr, "[DEBUG] length: %lld / %d\n", length, inf->buffer_length);
        inf->buffer_length += length;
        
        if(ph == NULL && length < sizeof(packetHeader)) {
            // PRVA CAST MUSI MAT VELKOST ASPON HLAVICKY
            log(stderr,"[DEBUG] too short packet, without header ???\n");
            
            Node::shutdown(inf);
            
            return;
        } else if(ph == NULL) {
            ph = new packetHeader;
            memcpy(ph, buffer, sizeof(packetHeader));
            
            log(stderr, "[DEBUG] packet length: %lld\n", ph->length);
        }
        
        if(length < 0) {
            log(stderr,"[DEBUG] evbuffer_remove < 0\n");
            Node::shutdown(inf);
            
            if(ph != NULL)
                delete ph;
            return;
        }
        
        dataList *tmp = new dataList;
        tmp->data = new char[length];
        memcpy(tmp->data, buffer, length);
        tmp->length = length;
        
        if(length == ROUTER_BUFFER) {
            inf->buffer.push(tmp);
        } else {
            log(stderr,"[DEBUG] mensie, asi koniec paketu ?\n");
            
            // SIZE OF PACKET HEADER + DATA
            int packetSize = (ph->length + sizeof(packetHeader));
            int estimate = inf->buffer_length - packetSize;
            
            // NOT COMPLETE
            if(estimate < 0) {
                inf->buffer.push(tmp);
                log(stderr,"[DEBUG] pokracujem v citani paketu\n");
                continue;
            } else {
                char *buff = NULL;
                dataList *ltmp = NULL;
                char *tmpbuf = NULL;
                
                if(estimate > 0) {
                    tmpbuf = tmp->data;
                    tmp->data = new char[length - estimate];
                    tmp->length = length - estimate;
                }
                
                buff = new char[packetSize];
                
                int lentmp = 0;
                
                // BUILD PACKET
                while(inf->buffer.empty() == false) {
                    ltmp = inf->buffer.front();
                    memcpy(buff+lentmp, ltmp->data, ltmp->length);
                    lentmp += ltmp->length;
                    inf->buffer.pop();
                    
                    delete ltmp;
                }
                
                // ADD LAST PART OF PACKET
                memcpy(buff+lentmp, tmp->data, tmp->length);
                
                // CREATE PACKET
                Packet *p = new Packet;
                
                // SET LOCAL DELIVERY
                p->setLocalDelivery(); 
                
                if(p->parsePacket(buff, packetSize) == false) {
                    log(stderr,"[DEBUG] paket nie je validny\n");
                    Node::shutdown(inf);
                    
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
                
                DatabasePacket::instance()->add(p);
                
                // PARSE REMAINING DATA
                char *delbuf = tmpbuf;
                while(tmpbuf != NULL) {
                    ph = new packetHeader;
                    memcpy(ph, buffer, sizeof(packetHeader));
                    
                    int packetSize = ph->length + sizeof(packetHeader);
                    if(estimate >= packetSize) {
                        buff = new char[packetSize];
                        memcpy(buff, tmpbuf, packetSize);
                        
                        Packet *p = new Packet;
                        p->setLocalDelivery(); // FROM REMOTE RESOURCE
                        
                        if(p->parsePacket(buff, ph->length + sizeof(packetHeader)) == false) {
                            log(stderr,"[DEBUG] paket nie je validny\n");
                            Node::shutdown(inf);
                            
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
                        
                        //inf->s->insertPacket(p);
                        estimate -= ph->length + sizeof(packetHeader);
                        tmpbuf += ph->length + sizeof(packetHeader);
                    } else {
                        
                    }
                }
                if(delbuf != NULL)
                    delete delbuf;
            }
        }
    }
}
*/
void Node::writeCallback(struct bufferevent *bev, void *arg) {
    log(stderr,"[DEBUG] write callback\n");     
}


void Node::eventCallback(struct bufferevent *bev, short event, void *ptr) {
    log(stderr,"[DEBUG] event callback\n");
    if (event & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        // FREE AND CLOSE CONNECTION
        Node::shutdown((nodeInfo *)ptr);
    }
}

void Node::shutdown(nodeInfo *inf) {
    node *n = inf->n;
    
    log(stderr,"[DEBUG] NODE::shutdown\n");
    
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