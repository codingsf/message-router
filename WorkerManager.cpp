//
//  WorkerManager.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 12.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "WorkerManager.h"


void WorkerManager::start(unsigned int workers) {
    for(int i=0; i < workers; i++) {
        Worker *w = new Worker();
        pthread_create(w->getThread(), NULL, Worker::start, (void *)w);
        
        Manager::instance()->addWorker(w);
    }
}
