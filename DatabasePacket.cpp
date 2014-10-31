//
//  DatabasePacket.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 13.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "DatabasePacket.h"

DatabasePacket *DatabasePacket::inst = 0;

DatabasePacket *DatabasePacket::instance() {
    if(!inst)
        inst = new DatabasePacket();
    return inst;
}

bool DatabasePacket::add(Packet *p) {
    MLOCK(&mutex);
    log(stderr, "[DEBUG] insert packet\n");
    packets.push(p);
    pthread_cond_signal(&cond);
    MUNLOCK(&mutex);
    return true;
}

Packet *DatabasePacket::get() {
    
    MLOCK(&mutex);
    while(packets.empty())
        pthread_cond_wait(&cond, &mutex);
    
    Packet *p = packets.front();
    packets.pop();
    MUNLOCK(&mutex);
    return p;
}