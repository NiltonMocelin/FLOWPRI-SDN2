## REFF https://docs.cloudlab.us/geni-lib.html

"""An example of constructing a profile with node IP addresses specified
manually.

Instructions:
Wait for the profile instance to start, and then log in to either VM via the
ssh ports specified below.  (Note that even though the EXPERIMENTAL
data plane interfaces will use the addresses given in the profile, you
will still connect over the control plane interfaces using addresses
given by the testbed.  The data plane addresses are for intra-experiment
communication only.)
"""

import geni.portal as portal
import geni.rspec.pg as rspec

request = portal.context.makeRequestRSpec()

node1 = request.XenVM("node1")
iface1 = node1.addInterface("if1")

# Specify the component id and the IPv4 address
iface1.component_id = "eth1"
iface1.addAddress(rspec.IPv4Address("192.168.1.1", "255.255.255.0"))

node2 = request.XenVM("node2")
iface2 = node2.addInterface("if2")

# node1.hardware_type = "m400" # o Tipo de hardware determina a regiao m400 eh hardware de Utah -> ver https://docs.cloudlab.us/hardware.html
# node2.hardware_type = "m400"

# Specify the component id and the IPv4 address
iface2.component_id = "eth2"
iface2.addAddress(rspec.IPv4Address("192.168.1.2", "255.255.255.0"))

link = request.LAN("lan")

link.addInterface(iface1)
link.addInterface(iface2)

portal.context.printRequestRSpec()