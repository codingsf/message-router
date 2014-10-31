//
//  DatabaseNode.h
//  ChatRouter
//
//  Created by Patrik Štrba on 13.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__DatabaseNode__
#define __ChatRouter__DatabaseNode__

#include <iostream>
#include "structure.h"

class DatabaseNode {
public:
    static DatabaseNode *instance();
    
    bool queueAdd(std::string k, node *n);
    node *queuePop(std::string k);
    
    bool add(key k, node *c);
    node *get(key k);
    bool remove(key k);
    
    // SUPERNODE
    void setSuperNode(node *n);
    node *getSuperNode();
private:
    DatabaseNode(): superNode(NULL) {}
    
    node *superNode;
    
    // NODES
    MAPN nodes;
    
    // NODES-QUEUE
    MAPQ nodesQ;
    
    // SINGLETOM
    static DatabaseNode *inst;
};

#endif /* defined(__ChatRouter__DatabaseNode__) */
