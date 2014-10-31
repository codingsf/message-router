//
//  Node.h
//  ChatRouter
//
//  Created by Patrik Štrba on 12.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__Node__
#define __ChatRouter__Node__

#include <iostream>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/thread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "structure.h"

#include "Manager.h"
#include "Packet.h"

#include "DatabaseNode.h"
#include "DatabasePacket.h"

class Node {
public:
    static Node *instance();
    
    void start(unsigned int port);
    
    
    /* STATIC METHODS */
    static void *start(void *ptr);
    static void acceptCallback(evutil_socket_t fd, short ev, void *arg);
    static void readCallback(struct bufferevent *bev, void *ptr);
    static void writeCallback(struct bufferevent *bev, void *arg);
    static void eventCallback(struct bufferevent *bev, short event, void *ptr);
    
    static void shutdown(nodeInfo *inf);
    
    pthread_t *getThread() { return &thread; }
    
    void setPort(unsigned int port) { this->port = port; }
    unsigned int getPort() { return port; }
    
    event_base *getBase() { return base; }
    void setBase(event_base *base) { this->base = base; }
    
    bool isActive() { return running; }
    
    // NODES
    MAPN nodes;
    
    // NODES-QUEUE
    MAPQ nodesQ;
    
    // CLIENTS
    MAPSK clients;
    
private:
    
    Node():running(true) {}
    
    // PORT
    unsigned int port;
    
    // BASE
    event_base *base;
    
    // THREAD
    pthread_t thread;
    
    // SINGLETON
    static Node *inst;
    
    // STATUS
    bool running;

};

#endif /* defined(__ChatRouter__Node__) */
