//
//  Server.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 26.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "Server.h"
#include "ControllerServer.h"

Server *Server::inst = 0;

Server *Server::instance() {
    if(!inst)
        inst = new Server();
    return inst;
}


bool Server::start(unsigned int port) {
    this->initMutex();
    
    if(evthread_use_pthreads() != 0) {
        printf("ERROR: libevent thread error\n");
        return false;
    }
    
    this->setPort(port);
    
    pthread_create(this->getThread(), NULL, Server::start, (void *)Manager::instance());
    return true;
}

void *Server::start(void *ptr) {
    Manager *m = (Manager *)ptr;
    
    libwebsock_context *ctx = NULL;
    
    if((ctx = libwebsock_init()) == NULL) {
        fprintf(stderr, "Error during libwebsock_init.\n");
        exit(1);
    }
    
    libwebsock_bind(ctx, "0.0.0.0", m->getServer()->getPort());
    
    ctx->onmessage = Server::onMessage;
    ctx->onopen = Server::onOpen;
    ctx->onclose = Server::onClose;
    
    log(stderr, "[DEBUG] SERVER start listening\n");
    
    libwebsock_wait(ctx);
    
    // STOP ROUTER
    event_base_loopbreak(m->getRouter()->getBase());
    
    m->getServer()->destroyMutex();
    return NULL;
}

int Server::onMessage(libwebsock_client_state *state, libwebsock_message *msg) {
    Packet *pack = new Packet;
    
    // GET CLIENT BY SOCK
    Client *c = getClient(state->sockfd);
    
    if(pack->parsePacket(msg->payload, msg->payload_len) == false) {
        // INVALID PACKET
        fprintf(stderr, "[DEBUG] WRONG PACKET FORMAT\n");
        delete pack;
        return -1;
    }
    
    pack->debug();
    
    // PROCESS PACKET
    ControllerServer::init(pack, c);
    return 0;
}

int Server::onOpen(libwebsock_client_state *state) {
    Client *c;
    
    c = new Client(state->sockfd, state->bev);
    
    // CREATE NEW CLIENT
    insert(state->sockfd, c);
    
    // DEBUG
    log(stderr, "[DEBUG] CONNECT: %d\n", state->sockfd);
    
    return 0;
}

int Server::onClose(libwebsock_client_state *state) {
    // REMOVE CLIENT + DELETE OBJECT
    remove(state->sockfd);

    // DEBUG
    log(stderr, "[DEBUG] DISCONNECT: %d\n", state->sockfd);
    
    return 0;
}

void Server::insert(int sock, Client *c) {
    Server::instance()->cmap[sock] = c;
}

void Server::remove(int sock) {
    Client *c = Server::instance()->cmap[sock];
    
    if(c->isAuth()) {        
        DatabaseClient::instance()->remove( *(c->getKey()) );

        /*
        MAPK::iterator it = Server::instance()->clients.find(*(c->getKey()));
        
        for(;it->first == *(c->getKey()); it++) {
            if(it->second->getSock() == c->getSock()) {
                // REMOVE FROM MULTIMAP BY SOCK
                Server::instance()->clients.erase(it);
                break;
            }
        }
        */
    }
    
    // DELETE CLIENT
    delete c;
    
    // REMOVE FROM MAP BY SOCK
    Server::instance()->cmap.erase(sock);
}

Client *Server::getClient(int sock) {
    return Server::instance()->cmap[sock];
}

void Server::initMutex() {
    pthread_mutex_init(&mutex, NULL);
    pthread_mutex_init(&mutex_node, NULL);
    pthread_cond_init(&cond, NULL);
}
void Server::destroyMutex() {
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&mutex_node);
    pthread_cond_destroy(&cond);
}