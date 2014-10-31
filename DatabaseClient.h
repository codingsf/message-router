//
//  DatabaseClient.h
//  ChatRouter
//
//  Created by Patrik Štrba on 13.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__DatabaseClient__
#define __ChatRouter__DatabaseClient__

#include <iostream>
#include "structure.h"

class DatabaseClient {
public:
    static DatabaseClient *instance();
    
    bool addClient(Client *c, key k);
    Client *getClient(key k);
    bool remove(key k);

    
private:
    DatabaseClient() {
    }
    
    MAPSK clients;
    
    // SINGLETOM
    static DatabaseClient *inst;
};

#endif /* defined(__ChatRouter__DatabaseClient__) */
