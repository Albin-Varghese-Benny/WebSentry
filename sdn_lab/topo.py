"""
topo.py -- the WebSentry network.

     h1 alice (10.0.0.1) --\
     h2 bob   (10.0.0.2) ---+-- s1 ======== s2 --+-- proxy (10.0.0.10)   proxy.py: TLS 8443, plain 8080
     h3 anon  (10.0.0.3) --/   (access)  (core)   +-- svc   (10.0.0.20)   services.py: web/chat/echo/files/bulk

All switches are Open vSwitch speaking OpenFlow 1.3 to one remote Ryu controller. Hosts sit on one /24, so
the only thing that keeps the clients away from the services is the controller's flow table.
Client links are TCLinks so bandwidth, delay and loss can be set per experiment.
"""
from mininet.link import TCLink
from mininet.topo import Topo

IPS = {"h1": "10.0.0.1", "h2": "10.0.0.2", "h3": "10.0.0.3", "proxy": "10.0.0.10", "svc": "10.0.0.20"}
USERS = {"h1": "alice", "h2": "bob", "h3": None}              # None = anonymous (no client certificate)
CLIENTS = ("h1", "h2", "h3")


class WebSentryTopo(Topo):
    def build(self, client_bw=20, client_delay="2ms", client_loss=0):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        for i, name in enumerate(CLIENTS, start=1):
            h = self.addHost(name, ip=f"{IPS[name]}/24", mac=f"00:00:00:00:00:0{i}")
            self.addLink(h, s1, cls=TCLink, bw=client_bw, delay=client_delay, loss=client_loss)
        self.addLink(s1, s2, cls=TCLink, bw=100)
        proxy = self.addHost("proxy", ip=f"{IPS['proxy']}/24", mac="00:00:00:00:00:10")
        svc = self.addHost("svc", ip=f"{IPS['svc']}/24", mac="00:00:00:00:00:20")
        self.addLink(proxy, s2, cls=TCLink, bw=100)
        self.addLink(svc, s2, cls=TCLink, bw=100)


topos = {"websentry": WebSentryTopo}
