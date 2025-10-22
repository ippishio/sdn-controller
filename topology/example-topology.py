from mininet.net import Mininet
from mininet.node import OVSSwitch, OVSBridge, RemoteController


network = Mininet()

s1 = network.addSwitch("s1", cls=OVSSwitch)
s2 = network.addSwitch("s2", cls=OVSSwitch)
br_ex = network.addSwitch("br-ex", cls=OVSBridge, ip="10.0.0.254/24")

h1 = network.addHost("h1", ip="10.0.0.1/24")
h2 = network.addHost("h2", ip="10.0.0.2/24")
v1 = network.addHost("v1", ip="10.0.0.3/24")
v2 = network.addHost("v2", ip="10.0.0.4/24")

c0 = network.addController("c0", controller=RemoteController(ip="127.0.0.1", port=6653))
network.addLink(s1, h1)
network.addLink(s1, h2)
network.addLink(s2, v1)
network.addLink(s2, v2)
network.addLink(br_ex, s1)
network.addLink(br_ex, s2)

network.build()
c0.start()
br_ex.start([c0])
