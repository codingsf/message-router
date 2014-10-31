//
//  Packet.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 28.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "Packet.h"

bool Packet::parsePacket(char *data, unsigned long long length) {
    unsigned long long data_length;
    
    // CHECK MINIMAL SIZE OF PACKET
    if(length < sizeof(packetHeader))
         return false;
    
    p = new packet;
    memcpy(p, data, sizeof(packetHeader));
    
    data_length = length - sizeof(packetHeader);
    
    // CHECK SIZE OF DATA LENGTH
    if(data_length != p->header.length)
        return false;
    
    
    if(data_length == 0) {
        p->data = NULL;
    } else {
        p->data = new unsigned char[data_length];
        memcpy(p->data, data+sizeof(packetHeader), data_length);
    }

    return true;
}

void Packet::error(char *message) {
    if(p != NULL)
        delete p;
    
    p = new packet;
    // TODO: set source
    //p->setLocalSource();
    p->header.type = PACKET_ERROR;
    p->header.length = strlen(message);
    p->data = (unsigned char *)message;
}

unsigned char *Packet::getFullPacket() {
    if(p == NULL)
        return NULL;
    
    if(full != NULL)
        return full;
    
    unsigned long long size = sizeof(packetHeader) + this->getLength();
    
    unsigned char *data = new unsigned char[size];
    memcpy(data, &p->header, sizeof(packetHeader));
    memcpy(data+sizeof(packetHeader), p->data, getLength());
    return data;
}

unsigned char *Packet::getData() {
    return p->data;
}

int Packet::getType() {
    return p->header.type;
}

unsigned long long Packet::getLength() {
    return p->header.length;
}

key *Packet::getDestination() {
    return &(p->header.destination);
}

key *Packet::getSource() {
    return &(p->header.source);
}

void Packet::setData(unsigned char *data) {
    p->data = data;
}

void Packet::setType(int type) {
    p->header.type = type;
}

void Packet::setLength(unsigned int length) {
    p->header.length = length;
}

void Packet::setDestination(key *k) {
    memcpy(&(p->header.destination), k, sizeof(key));
}

void Packet::setSource(key *k) {
    memcpy(&(p->header.source), k, sizeof(key));
}
