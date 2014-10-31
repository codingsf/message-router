//
//  Router.h
//  ChatRouter
//
//  Created by Patrik Štrba on 28.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__Router__
#define __ChatRouter__Router__

#include <iostream>
#include <cstdlib>
#include <cstring>

#include "config.h"
#include "structure.h"
#include "Manager.h"

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class Router {
public:
    static Router *instance();
    
    Router(): base(NULL) {}
    
    void start(unsigned int port);
    
    static void *start(void *ptr);
    static void acceptCallback(evutil_socket_t fd, short ev, void *arg);
    static void readCallback(struct bufferevent *bev, void *ptr);
    static void writeCallback(struct bufferevent *bev, void *arg);
    static void eventCallback(struct bufferevent *bev, short event, void *ptr);
    //static void readBuffer(evutil_socket_t socket, short flags, void *ptr);
    
    static void shutdown(nodeInfo *inf);
    
    pthread_t *getThread() {
        return &thread;
    }
    unsigned int getPort() { return port; }
    event_base *getBase() { return base; }
    void setBase(event_base *base) { this->base = base; }
    
    void setServer(Server *s) { this->s = s; }
    Server *getServer() { return s; }
private:
    pthread_t thread;
    
    unsigned int port;
    event_base *base;
    
    Server *s;
    
    static Router *inst;
};

#endif /* defined(__ChatRouter__Router__) */
