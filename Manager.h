//
//  Manager.h
//  ChatRouter
//
//  Created by Patrik Štrba on 8.4.2013.
//  Copyright (c) 2013 Patrik Štrba. All rights reserved.
//

#ifndef __ChatRouter__Manager__
#define __ChatRouter__Manager__

#include <iostream>
#include <queue>

class Server;
class Router;
class Node;
class Worker;

class Manager {
public:
    static Manager *instance();
    
    Server *getServer() { return s; }
    Router *getRouter() { return r; }
    Node   *getNode()   { return n; }
    
    void setServer(Server *s) { this->s = s; }
    void setRouter(Router *r) { this->r = r; }
    void setNode  (Node *n)   { this->n = n; }
    
    void addWorker(Worker *w);
    
    void setSuperNode() { supernode = true; }
    bool isSuperNode() { return supernode; }
    
    
    bool isActive();
private:
    Manager() {
        supernode = false;
    }
    Server *s;
    Router *r;
    Node *n;
    
    // SUPERNODE
    bool supernode;
    
    // WORKERS LIST
    std::queue<Worker *> workers;
    
    // SINGLETON
    static Manager *inst;
    
};
    

#endif /* defined(__ChatRouter__Manager__) */
