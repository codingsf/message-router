//
//  Worker.h
//  ChatRouter
//
//  Created by Patrik Štrba on 27.3.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__Worker__
#define __ChatRouter__Worker__

#include <iostream>
#include <pthread.h>
#include "structure.h"
#include "Client.h"
#include "Server.h"
#include "DatabasePacket.h"

class Worker {
public:
    Worker() {
    }
    
    void loopNode();
    void loopSuperNode();
    
    pthread_t *getThread() {
        return &thread;
    }
    
    static void *start(void *ptr);
private:
    pthread_t thread;
    
};

#endif /* defined(__ChatRouter__Worker__) */
