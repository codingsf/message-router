#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "config.h"
#include "Manager.h"
#include "Server.h"
#include "Node.h"
#include "WorkerManager.h"


#include <ctime>

char **getTXT(const char *name, int *size);

int main(int argc, char *argv[]) {
    //int maxClients;
    //int maxClientGroupKey = 5; // POCET MAXIMALNE PRIPOJENYCH POUZIVATELOV S TYM ISTYM KLUCOM
    
    bool supernode = false;
    
    int c;
    opterr = 0;
    
    while ((c = getopt (argc, argv, "nsc:")) != -1) {
        switch (c) {
        case 'n':
            supernode = false;
            break;
        case 's':
            supernode = true;
            break;
        case 'c':
            //cvalue = optarg;
            break;
        case '?':
            if (optopt == 'c')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            abort ();
        }
    }
    
    Manager *m = Manager::instance();
    
    if(supernode) {
        printf("STARTING SUPERNODE\n");
        Manager::instance()->setSuperNode();
        
        Node *n = Node::instance();
        n->start(NODE_PORT);
        // TODO: finish
        m->setNode(n);
        
        WorkerManager w;
        w.start(1);
        
        //printf("ERROR: SUPER-NODE IS NOT COMPLETE!!\n");
    } else {
        
        Server *s = Server::instance();
        m->setServer(s);
        s->start(LISTEN_PORT);
        
        Router *r = Router::instance();
        m->setRouter(r);
        r->start(ROUTER_PORT);
        
        WorkerManager w;
        w.start(1);
        
        // CONNECT TO SUPERNODE
        
         char *servers[2];
        servers[0] = "127.0.0.1";
        //servers[0] = "94.229.35.144";
         //servers[1] = "192.168.0.100";
         
        for(int i=0; i < 1; i++) {
            connection *conn = new connection;
            struct sockaddr_in *sin = new struct sockaddr_in;
            node *n = new node;
             
            conn->bev = NULL;
            memset(sin, 0, sizeof(struct sockaddr_in));
            sin->sin_family = AF_INET;
            sin->sin_port = htons(NODE_PORT);
            inet_pton(AF_INET, servers[i], &sin->sin_addr);
            conn->sin = sin;
            n->conn = conn;
            n->status = DISCONNECT;
            n->failed = 0;
            
            
            while(r->getBase() == NULL)
                continue;
            
            n->setSuperNode();
            n->connect(r->getBase());
            
            DatabaseNode::instance()->setSuperNode(n);
            
         
         //nodes.push_back(n);
        }
    }
    printf("[DEBUG]: CYKLUS\n");
    
    //while(m->getServer()->isActive())
    
    char cc;
    while(scanf("%c", &cc) >= 0) {
        if(c == '\n')
            continue;
        
        switch(cc) {
            case 's':
                printf("STATUS\n");
                
                if(supernode)
                    continue;
                
                MAPC *cmap = Manager::instance()->getServer()->getMapSock();
                MAPC::iterator it;
                
                for(it=cmap->begin(); it != cmap->end(); it++) {
                    Client *c = it->second;
                    
                    printf("CLIENT: SOCK[%d]\n", c->getSock());
                    printf("KEY: ");
                    
                    for(int i=0; i < sizeof(key); i++) {
                        printf("%#02x ", c->getKey()->data[i]);
                    }
                    printf("\n");
                }
                
                
            break;
        }
        //usleep(1000000);
    }
}


