//
//  Client.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 26.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "Client.h"
#include "websocket.h"
#include "Packet.h"

bool Client::auth(key *k, const unsigned char *data) {
    if(this->getHash() == NULL)
        return false;
    
    if(memcmp(data, getHash(), CLIENT_HASH_SIZE) != 0)
        return false;
    
    // SET STATUS AND KEY
    status = AUTH;
    
    memcpy(&id, k, sizeof(key));
    return true;
}

void Client::genHash() {
    hash = new unsigned char[CLIENT_HASH_SIZE];
    int i;
    for(i=0; i < CLIENT_HASH_SIZE; i++)
        hash[i] = rand() % 256;
}

Packet *Client::handshake(const unsigned char *data, unsigned int length) {
    // AUTHENTICATE CLIENT
    RSAutil rsa;
    
    // LOAD CLIENT PUB KEY
    if(rsa.loadKey(data, length) == false) {
        //log(stderr, "[DEBUG] PUBLIC KEY WRONG\n");
        //Packet err;
        //err.error("WRONG KEY");
        //this->sendPacket(&err);
        
        throw "[DEBUG] PUBLIC KEY WRONG";
    }
    
    // CREATE AND SAVE PUBLIC KEY
    pubkey = new unsigned char[length+1];
    memset(pubkey, 0, length);
    memcpy(pubkey, data, length);
    
    // GENERATE HASH
    this->genHash();
    
    status = HANDSHAKE;
    
    int size=0;
    unsigned char *tmp = rsa.encode(this->getHash(), CLIENT_HASH_SIZE, &size);
    
    Packet *pa = new Packet;
    packet *p = new packet;

    pa->setPacket(p);
    pa->setLength(size);
    pa->setData(tmp);
    
    pa->setPacket(p);
    printf("RET HANDSHAKE\n");
    return pa;
}

void Client::sendPacket(Packet *p) {
    libwebsock_client_state state;
    memset(&state, 0, sizeof(libwebsock_client_state));
    
    char *buff;
    
    buff = new char[sizeof(packetHeader) + p->getLength()];
    memcpy(buff, &p->getPacket()->header, sizeof(packetHeader));
    memcpy(buff+sizeof(packetHeader), p->getPacket()->data, p->getLength());
    
    state.bev = this->bev;
    libwebsock_send_binary(&state, buff, sizeof(packetHeader) + p->getLength());
    
    delete buff;
}