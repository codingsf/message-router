//
//  Manager.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 8.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "Manager.h"
#include "Node.h"
#include "Server.h"

Manager *Manager::inst = 0;

Manager *Manager::instance() {
    if(!inst)
        inst = new Manager();
    return inst;
}

void Manager::addWorker(Worker *w) {
    workers.push(w);
}

bool Manager::isActive() {
    if(supernode)
        return n->isActive();
    else
        return s->isActive();
}