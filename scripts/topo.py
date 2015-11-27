# -*- coding: utf-8 -*-
# Author: Pedro Martinez-Julia (pedromj@um.es)

from mininet.topo import Topo

class MyTopo (Topo):

    def __init__ (self):
        Topo.__init__( self )

        # Add switches
        sw_clients = self.addSwitch('s1')
        sw_servers = self.addSwitch('s2')

        # Add clients
        c1 = self.addHost('cli_1')
        c2 = self.addHost('cli_2')
        c3 = self.addHost('cli_3')
        c4 = self.addHost('cli_4')
        c5 = self.addHost('cli_5')
        c6 = self.addHost('cli_6')

        # Add servers
        s1 = self.addHost('srv_1', ip='10.0.0.101', mac='00:00:00:00:01:01')
        s2 = self.addHost('srv_2', ip='10.0.0.101', mac='00:00:00:00:01:02')
        s3 = self.addHost('srv_3', ip='10.0.0.101', mac='00:00:00:00:01:03')
        s4 = self.addHost('srv_4', ip='10.0.0.101', mac='00:00:00:00:01:04')

        # Add links
        self.addLink(sw_clients, sw_servers, port2=1)

        self.addLink(c1, sw_clients)
        self.addLink(c2, sw_clients)
        self.addLink(c3, sw_clients)
        self.addLink(c4, sw_clients)
        self.addLink(c5, sw_clients)
        self.addLink(c6, sw_clients)

        self.addLink(s1, sw_servers, port2=2)
        self.addLink(s2, sw_servers, port2=3)
        self.addLink(s3, sw_servers, port2=4)
        self.addLink(s4, sw_servers, port2=5)


topos = {'mytopo': lambda: MyTopo()}
