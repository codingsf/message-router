//
//  Client.h
//  ChatRouter
//
//  Created by Patrik Štrba on 26.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__Client__
#define __ChatRouter__Client__

#include <iostream>
#include "structure.h"
#include "RSAutil.h"

enum state {
    NONE = 0, // LOGOUT, FIRST PHASE
    HANDSHAKE = 1, // TRY TO AUTH, SECOND PHASE
    AUTH = 2 // CORRECT AUTHENTICATE
};

class Client {
    
public:
    Client(int socket = NULL, struct bufferevent *b = NULL):
        status(NONE),
        hash(NULL),
        pubkey(NULL),
        sock(socket),
        bev(b) {
            
    }
    
    ~Client() {
        if(pubkey != NULL) {
            delete pubkey;
            pubkey = NULL;
        }
    }

    bool auth(key *k, const unsigned char *data);
    
    bool isAuth() {
        return status == AUTH;
    }
    
    bool isReady() {
        return isAuth();
    }
    
    state getStatus() {
        return status;
    }
    
    int getSock() { return sock; }
    
    void setKey(key *k) { memcpy(&id, k, sizeof(key)); }
    key *getKey() { return &id; }
    
    void sendPacket(Packet *p);
    
    void genHash();
    unsigned char *getHash() { return hash; }
    
    Packet *handshake(const unsigned char *data, unsigned int length);
    
    
    void setNode(node *n) { this->n = n; }
    node *getNode() { return n; }
    
    void setAuth() { status = AUTH; }
    void setLogout() { status = NONE; }
    
private:
    key id;
    state status;
    
    unsigned char *pubkey;
    
    node *n;
    
    int sock;
    struct bufferevent *bev;
    
    unsigned char *hash;
};
    
#endif /* defined(__ChatRouter__Client__) */
