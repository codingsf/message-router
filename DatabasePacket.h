//
//  DatabasePacket.h
//  ChatRouter
//
//  Created by Patrik Štrba on 13.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__DatabasePacket__
#define __ChatRouter__DatabasePacket__

#include <iostream>
#include <pthread.h>
#include "structure.h"
#include "Packet.h"

class DatabasePacket {
public:
    static DatabasePacket *instance();
    
    
    bool add(Packet *p);
    Packet *get();
    
    ~DatabasePacket() {
        MLOCK(&mutex);
        while(packets.size() > 0) {
            Packet *pack = packets.front();
            delete pack;
            
            packets.pop();
        }
        
        MUNLOCK(&mutex);
        
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
    }
private:
    DatabasePacket() {
        pthread_mutex_init(&mutex, NULL);
        pthread_cond_init(&cond, NULL);
    }
    
    MAPR packets;
    
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    
    // SINGLETOM
    static DatabasePacket *inst;
};

#endif /* defined(__ChatRouter__DatabasePacket__) */
