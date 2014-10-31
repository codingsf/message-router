//
//  Worker.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 27.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//
#include <cstdio>
#include "Worker.h"
#include "DatabaseClient.h"

void *Worker::start(void *ptr) {
    Worker *w = reinterpret_cast<Worker *>(ptr);
    
    if(Manager::instance()->isSuperNode()) {
        w->loopSuperNode();
    } else {
        w->loopNode();
    }
    
    delete w;
    
    return NULL;
}

void Worker::loopNode() {
    Packet *p;
    
    Manager *m = Manager::instance();
    
    log(stderr,"[DEBUG] WORKER start\n");
    
    while(m->isActive()) {
        if((p = DatabasePacket::instance()->get()) == NULL)
            continue;
        
        log(stderr, "[DEBUG] MAM PACKET\n");
        
        //p->debug();
        
        Client *c = DatabaseClient::instance()->getClient( *(p->getDestination()) );
        
        switch(p->getType()) {
            case PACKET_AUTH_ACCEPT:
                if(p->getNode()->isSuperNode() == false) {
                    log(stderr, "[DEBUG] WRONG SOURCE FOR THIS PACKET TYPE\n");
                    delete p;
                    continue;
                }
                
                c->setAuth();
                break;
        }
        
        if(c != NULL) {
            c->sendPacket(p);
            log(stderr, "[DEBUG] ODOSLANE\n");
        } else {
            log(stderr, "[DEBUG] ADRESAT NEEXISTUJE\n");
            p->debug();
        }
        
        delete p;
        
        /*
        if(p->isExternalDelivery() == false) {
            // LOCAL DELIVERY
            
            log(stderr, "[DEBUG] WORKER local route\n");
            
            MAPK::iterator it;
            
            it = s->clients.find(*p->getDestination());
            if(it->first == *p->getDestination()) {
                // INTERNAL ROUTE
                
                log(stderr, "[DEBUG] WORKER local route\n");
                
                for(;it->first == *p->getDestination(); it++)  // SEND TO ALL CLIENTS WITH THE SAME KEY
                    it->second->sendPacket(p);
                
                delete p;
            } else {
                // CLIENT IS NOT ONLINE - OR WRONG ROUTE
                log(stderr, "[DEBUG] WORKER wrong local deliver - unknown client\n");
                
                // TODO
                // VYGENEROVAT SPRAVU O NEUSPESNOM DORUCENI
                
                delete p;
            }
            
            continue;
        } else {
            if(s->clients_node[p->getPacket()->header.destination] == NULL) {
                log(stderr, "[DEBUG] NEVIEM KDE SA NACHADZA :(\n");
                if(p->getType() != PACKET_HANDSHAKE) {
                    // AK CHCEME ODOSLAT OD LOKALNE KLIENTA PAKET EXTERNE, TAK JE MOZNE VYHLADAVANIE LEN PRI HANDSHAKE
                    Packet *pack = new Packet;
                    pack->error("NO ENTRY");
                    pack->setDestination(p->getSource());
                    
                    s->insertPacket(pack);
                    
                    delete p;
                    continue;
                } else {
                    // SEARCH CLIENT VYHLADANIE NA KTOROM SERVERI SA NACHADZA
                    if(p->isRouted()) {
                        time_t t;
                        time(&t);
                        if(difftime(t, *p->getTime()) < ROUTER_RESPONSE_TIMEOUT) {
                            // STILL WAIT UNTIL TIMEOUT
                            s->insertPacket(p);
                            continue;
                        }
                        // NOW TIMEOUT LEFT AND MUST CONTACT ALL NODES :(
                    }
                    
                    LISTNODE::iterator it;
                    for(it = s->nodes.begin(); it != s->nodes.end(); it++) {
                        node *n = *it;
                        
                        
                        Packet *pack = new Packet;
                        pack->setPacket(new packet);
                        pack->setType(PACKET_SEARCH);
                        pack->getPacket()->data = new unsigned char[sizeof(key)];
                        memcpy(pack->getPacket()->data, p->getDestination(), sizeof(key));
                        
                        if(n->status == CONNECT && p->isRouted() == false) {
                            // POSLE ZIADOST CI NEEXISTUJE USER NA TOMTO NODE
                            struct evbuffer *buf = bufferevent_get_output(n->conn->bev);
                            
                            if(evbuffer_add(buf, pack->getFullPacket(), pack->getFullLength()) != 0) {
                                // CHYBA PRI POSIELANI :(
                                log(stderr,"[DEBUG] evbuffer_add error\n");
                            }
                            delete pack;
                        } else {
                            if(n->status == DISCONNECT && p->isRouted()) {
                                n->pushPacket(pack);
                                if(n->connect(m->getRouter()->getBase()) == false) {
                                    log(stderr, "[DEBUG] WORKER ERROR CONNECT\n");
                                }
                            }
                        }
                    }
                    
                    if(p->isRouted() == false) {
                        p->setRouted();
                    } else
                        delete p;
                }
            } else {
                node *n = s->clients_node[p->getPacket()->header.destination];
                
                if(n->status == DISCONNECT) {
                    // WE MUST CONNECT FIRST
                    if(n->failed >= ROUTER_MAX_FAILED_CONNECTION) {
                        // FAILED WE CANT CONNECT
                        Packet *pack = new Packet;
                        pack->error("NO CONNECT");
                        pack->setDestination(p->getSource());
                        
                        s->insertPacket(pack);
                        delete p;
                    }
                    
                    if(n->connect(m->getRouter()->getBase()) == false) {
                        log(stderr, "[DEBUG] WORKER ERROR CONNECT\n");
                        delete p;
                        continue;
                    }
                }
                
                if(n->status == CONNECTING) {
                    s->insertPacket(p);
                    continue;
                }
                
                log(stderr,"[DEBUG] NODE CONNECT\n");
                
                if(n->status == CONNECT) {
                    struct evbuffer *buf = bufferevent_get_output(n->conn->bev);
                    
                    unsigned long long size = sizeof(packetHeader) + p->getPacket()->header.length;
                    
                    p->debug();
                    
                    char *data = new char[size];
                    memcpy(data, &p->getPacket()->header, sizeof(packetHeader));
                    memcpy(data+sizeof(packetHeader), p->getPacket()->data, p->getPacket()->header.length);
                    
                    if(evbuffer_add(buf, data, size) != 0) {
                        // CHYBA PRI POSIELANI :(
                        log(stderr,"[DEBUG] evbuffer_add error :(\n");
                    }
                    
                    delete data;
                    delete p;
                }
            }
        }
        */
    }
}
void Worker::loopSuperNode() {
    Packet *p;
    
    Client *c;
    key *k;
    
    log(stderr,"[DEBUG] WORKER start\n");
    
    while(Manager::instance()->isActive()) {
        if((p = DatabasePacket::instance()->get()) == NULL)
            continue;
        
        log(stderr, "[DEBUG] MAM PACKET\n");
        
        switch(p->getType()) {
            case PACKET_AUTH:
                // CREATE CLIENT's KEY BY PUBKEY
                k = reinterpret_cast<key *>(RSAutil::sha256(p->getData(), p->getLength()));
                
                
                c = DatabaseClient::instance()->getClient( *k );
                
                if(c == NULL) {
                    c = new Client;
                    DatabaseClient::instance()->addClient(c, *k);
                }
                
                if(c->getHash() != NULL) {
                    p->debug();
                    log(stderr, "[DEBUG] Duplicate authentification same client\n");
                    delete p;
                    continue;
                }
                // AUTH PACKET
                log(stderr, "[DEBUG] AUTH\n");
                
                // k == p-getSource()
                
                try {
                    // GET RESPONSE PACKET
                    Packet *out = c->handshake(p->getData(), p->getLength());
                    
                    // SET DESTINATION
                    out->setDestination( k );
                    out->setType(PACKET_AUTH_HASH);
                    
                    // RETURN PACKET
                    printf("DBG AUTH SEND: %d\n", p->getNode()->sendPacket(out));
                    
                } catch(std::string e) {
                    printf("EXCEPTION: %s\n",e.c_str());
                }
                delete k;
                log(stderr, "[DEBUG] AUTH SUCCESS\n");
                break;
            case PACKET_AUTH_HASH:
                k = p->getSource();
                //p->debug();
                
                
                c = DatabaseClient::instance()->getClient( *k );
                
                if(c == NULL) {
                    
                    log(stderr, "[DEBUG] CLIENT DON'T EXISTS\n");
                    delete p;
                    
                    continue;
                }
                
                p->debug();
                
                if(c->auth(p->getSource(), p->getData()) == false) {
                    log(stderr, "[DEBUG] HASH WRONG\n");
                    delete p;
                    continue;
                } else
                    log(stderr, "[DEBUG] HASH VALID\n");
                
                try {
                    Packet *out = new Packet;
                    out->setPacket(new packet);
                    
                    // TODO: INSERT SOURCE KEY
                    //out->setSource( KEY )
                    
                    out->setDestination(p->getSource());
                    
                    out->setType(PACKET_AUTH_ACCEPT);
                    
                    // RETURN PACKET
                    p->getNode()->sendPacket(out);
                } catch(std::string e) {
                    log(stderr, e.c_str());
                    delete p;
                    continue;
                }
                
                
                /* DEBUGGING ONLY
                unsigned char *hash = RSAutil::sha256(pack->getSource()->data, sizeof(key));
                
                printf("[DEBUG] HASH: ");
                for(int i=0; i < sizeof(key); i++) {
                    printf("%02x", hash[i]);
                }
                printf("\n");
                */
                
                
                /*
                c->auth(k, p);
                Server * s = Manager::instance()->getServer();
                s->clients.insert( std::pair<key, Client *> (*(pack->getSource()),c));
                */
                break;
            case PACKET_HANDSHAKE:
                continue;
                break;
            case PACKET_SEARCH:
                // INPUT: client key
                // OUTPUT: node IP OR node key
                continue;
                break;
        }
        /*
        if(p->getType() == PACKET_AUTH_HASH) {
            if(c->auth(pack->getSource(), pack) == false) {
                log(stderr, "[DEBUG] HASH WRONG\n");
                delete p;
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
        }
         */
    }
}