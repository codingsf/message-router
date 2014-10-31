//
//  Server.h
//  ChatRouter
//
//  Created by Patrik Štrba on 26.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__Server__
#define __ChatRouter__Server__

#include <iostream>
#include <pthread.h>

#include "structure.h"
#include "websocket.h"
#include "Client.h"
#include "Worker.h"
#include "Packet.h"
#include "Router.h"
#include "RSAutil.h"

class Server {
public:
    static Server *instance();
    bool start(unsigned int port);
    
    static void *start(void *ptr);
    
    static int onMessage(libwebsock_client_state *state, libwebsock_message *msg);
    static int onOpen(libwebsock_client_state *state);
    static int onClose(libwebsock_client_state *state);
    
    static void insert(int sock, Client * c);
    static void remove(int sock);
    
    pthread_t *getThread() {
        return &thread;
    }
    
    void setPort(unsigned int port) {
        this->port = port;
    }
    
    unsigned int getPort() {
        return port;
    }
    
    MAPC *getMapSock() {
        return &cmap;
    }
    
    pthread_mutex_t *getNodeMutex() { return &mutex_node; }
    
    void initMutex();
    void destroyMutex();
    
    bool isActive() { return running; }
    
    // LIST NODES
    LISTNODE nodes;
    
    // MAP BY KEY -> NODE
    MAPN clients_node;
private:
    Server() {
        //printf("PACKET: %d\n", sizeof(packet));
        running = true;
    }
    
    // MAP BY sock
    MAPC cmap;
    
    static Client *getClient(int sock);
    
    pthread_t thread;
    
    unsigned int port;
    
    
    pthread_mutex_t mutex;
    pthread_mutex_t mutex_node;
    pthread_cond_t cond;
    
    // SINGLETON
    static Server *inst;
    
    // STATUS
    bool running;
};


#endif /* defined(__ChatRouter__Server__) */
