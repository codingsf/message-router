//
//  ServerController.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 25.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "ControllerServer.h"
#include "Server.h"

void ControllerServer::init(Packet *pack, Client *c) {
    
    // TEST USER LOGIN
    if(c->isAuth()) {
        stateLogin(pack, c);
    } else {
        stateLogout(pack, c);
    }
}

void ControllerServer::stateLogin(Packet *pack, Client *c) {
    /*
     log(stderr, "[DEBUG] route\n");
     
     // GET CLIENT BY DEST ADDR
     Client *dest = getClient(pack->getDestination());
     
     if(dest == NULL) {
     // EXTERNAL DELIVERY
     log(stderr, "[DEBUG] external packet\n");
     
     pack->setExternalDelivery(); // LOCAL PACKET
     Server::instance()->insertPacket(pack);
     } else {
     // LOCAL DELIVERY
     log(stderr, "[DEBUG] local route\n");
     
     for(;it->first == *pack->getDestination(); it++)  // SEND TO ALL CLIENTS WITH THE SAME KEY
     it->second->sendPacket(pack);
     
     delete pack;
     }
     */

    log(stderr, "[DEBUG] add to queue\n");
    DatabasePacket::instance()->add(pack);
}

void ControllerServer::stateLogout(Packet *pack, Client *c) {
    
    // FIRST TIME AUTH
    if(pack->getType() == PACKET_AUTH) {
        
        key *k = reinterpret_cast<key *> (RSAutil::sha256(pack->getData(), pack->getLength()));
        
        Client *ck = DatabaseClient::instance()->getClient(*k);
        
        // INSERT CLIENT IF NOT EXISTS
        if(ck == NULL) {
            DatabaseClient::instance()->addClient(c, *k);
            c->setKey(k);
        }
        
        if(pack->getSource()->compare(k) == false)
            pack->setSource(k);
        
        DatabaseNode::instance()->getSuperNode()->sendPacket(pack);
        /*
        if(c->getHash() != NULL) {
            log(stderr, "[DEBUG] Duplicate authentification same client\n");
            delete pack;
            return;
        }
        // AUTH PACKET
        log(stderr, "[DEBUG] AUTH\n");
        
        c->handshake(pack->getData(), pack->getLength());
        */
    } else if(pack->getType() == PACKET_AUTH_HASH) {
        //if(pack->getSource()->compare(c->getKey()) == false)
        //    pack->setSource(c->getKey());
        
        DatabaseNode::instance()->getSuperNode()->sendPacket(pack);
        /*
        if(c->auth(pack->getSource(), pack->getData()) == false) {
            log(stderr, "[DEBUG] HASH WRONG\n");
            delete pack;
            return;
        } else
            log(stderr, "[DEBUG] HASH VALID\n");
        
        pack->debug();
        //unsigned char *hash = RSAutil::sha256(pack->getPacket()->data, pack->getLength());
        unsigned char *hash = RSAutil::sha256(pack->getSource()->data, sizeof(key));
        
        printf("[DEBUG] HASH: ");
        for(int i=0; i < sizeof(key); i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
        
        Server * s = Manager::instance()->getServer();
        s->clients.insert( std::pair<key, Client *> (*(pack->getSource()),c));
         */
    }
    delete pack;
}