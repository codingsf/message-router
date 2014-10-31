//
//  RouterManager.h
//  ChatRouter
//
//  Created by Patrik Štrba on 13.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__RouterManager__
#define __ChatRouter__RouterManager__

#include <iostream>
#include "structure.h"

class RouterManager {
public:
    void addNode(node *n);
    
    LISTNODE *getNodes() { return &nodes; }
private:
    LISTNODE nodes;
};

#endif /* defined(__ChatRouter__RouterManager__) */
