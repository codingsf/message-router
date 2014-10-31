//
//  DatabaseNode.cpp
//  ChatRouter
//
//  Created by Patrik Štrba on 13.5.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#include "DatabaseNode.h"

DatabaseNode *DatabaseNode::inst = 0;

DatabaseNode *DatabaseNode::instance() {
    if(!inst)
        inst = new DatabaseNode();
    return inst;
}

bool DatabaseNode::queueAdd(std::string k, node *n) {
    nodesQ[k] = n;
    return true;
}

node *DatabaseNode::queuePop(std::string k) {
    node *n = NULL;
    
    n = nodesQ[k];
    nodesQ.erase(k);
    
    return n;
}

bool DatabaseNode::add(key k, node *c) {
    nodes[k] = c;
    return c;
}

node *DatabaseNode::get(key k) {
    return nodes[k];
}

bool DatabaseNode::remove(key k) {
    nodes.erase(k);
    return true;
}

void DatabaseNode::setSuperNode(node *n) {
    superNode = n;
}

node *DatabaseNode::getSuperNode() {
    return superNode;
}