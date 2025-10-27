from mininet.net import Mininet
from mininet.node import OVSSwitch, OVSBridge, RemoteController
from mininet.cli import CLI

network = Mininet()

s1 = network.addSwitch("s1", cls=OVSSwitch, dpid="1", protocols="OpenFlow13")
s2 = network.addSwitch("s2", cls=OVSSwitch, dpid="2", protocols="OpenFlow13")
br_ex = network.addSwitch(
    "br-ex",
    cls=OVSBridge,
    ip="10.0.0.254/24",
    dpid=str(0x1234),
    controller=None,
)

h1 = network.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
h2 = network.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
v1 = network.addHost("v1", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
v2 = network.addHost("v2", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

c0 = network.addController(
    "c0",
    controller=RemoteController,
    ip="127.0.0.1",
    port=6653,
    protocols="OpenFlow13",
)
network.addLink(s1, h1, 1, 1)
network.addLink(s1, h2, 2, 1)
network.addLink(s2, v1, 1, 1)
network.addLink(s2, v2, 2, 1)
network.addLink(br_ex, s1, 1, 3)
network.addLink(br_ex, s2, 2, 3)

network.start()
CLI(network)
network.stop()
