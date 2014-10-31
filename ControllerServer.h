//
//  ServerController.h
//  ChatRouter
//
//  Created by Patrik Štrba on 25.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__ServerController__
#define __ChatRouter__ServerController__

#include <iostream>
#include "Packet.h"
#include "Client.h"
#include "DatabaseNode.h"
#include "DatabaseClient.h"

class ControllerServer {
public:
    static void init(Packet *pack, Client *c);
    
    static void stateLogin(Packet *pack, Client *c);
    static void stateLogout(Packet *pack, Client *c);
    
    static void localDelivery();
    static void externalDelivery();
private:
    
};

#endif /* defined(__ChatRouter__ServerController__) */
