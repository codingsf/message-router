//
//  Packet.h
//  ChatRouter
//
//  Created by Patrik Štrba on 28.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__Packet__
#define __ChatRouter__Packet__

#include <iostream>
#include <ctime>
#include "structure.h"

class Packet {
public:
    Packet() {
        p = NULL;
        external = false;
        routed = false;
        full = NULL;
        src = NULL;
    }
    
    ~Packet() {
        if(p != NULL)
            delete p;
        
        if(full != NULL)
            delete full;
    }
    
    bool parsePacket(char *data, unsigned long long length);
    
    // TODO: MOVE TO .cpp FILE
    void setPacket(packet *p) { this->p = p; }
    packet *getPacket() { return p; }
    
    unsigned char *getData();
    int getType();
    unsigned long long getLength();
    key *getDestination();
    key *getSource();
    
    void setData(unsigned char *data);
    void setType(int type);
    void setLength(unsigned int length);
    void setDestination(key *key);
    void setSource(key *key);
    
    void setLocalDelivery() { external = false; }
    void setExternalDelivery() { external = true; }
    bool isExternalDelivery() { return external; }
    
    unsigned char *getFullPacket();
    unsigned long long getFullLength() { return getLength() + sizeof(packetHeader); }
    
    void error(char *message);
    
    void debug() { if(p != NULL) debugPacket(p); }
    
    void setRouted() { routed = true; }
    bool isRouted() { return routed; }
    time_t *getTime() { return &time; }
    
    void setNode(node *n) { src = n; }
    node *getNode() { return src; }
    
private:
    // PACKET STRUCTURE
    packet *p;
    unsigned char *full;
    
    // FD SOCK
    int sock;
    
    // NODE
    node *src;
    
    // INTERNAL/EXTERNAL DELIVERY
    bool external;
    
    // FOR EXTERNAL ROUTIME - TIMEOUT
    bool routed;
    time_t time;
};
    

#endif /* defined(__ChatRouter__Packet__) */
