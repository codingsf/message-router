//
//  DatabaseClient.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 13.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "DatabaseClient.h"
#include "exception"

DatabaseClient *DatabaseClient::inst = 0;

DatabaseClient *DatabaseClient::instance() {
    if(!inst)
        inst = new DatabaseClient();
    return inst;
}

bool DatabaseClient::addClient(Client *c, key k) {
    clients[k] = c;
    return true;
}

Client *DatabaseClient::getClient(key k) {
    return clients[k];
}

bool DatabaseClient::remove(key k) {
    if(getClient(k) == NULL)
        return false;
    
    clients.erase(k);
    
    return true;
}
