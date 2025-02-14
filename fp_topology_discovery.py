from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event
# Below is the library used for topo discovery
from ryu.topology.api import get_switch, get_link
import copy


## REF: https://github.com/Ehsan70/RyuApps/blob/master/TopoDiscoveryInRyu.md

###################################################################################
"""
    The event EventSwitchEnter will trigger the activation of get_topology_data().
"""
@set_ev_cls(event.EventSwitchEnter)
def handler_switch_enter(self, ev):
    # The Function get_switch(self, None) outputs the list of switches.
    self.topo_raw_switches = copy.copy(get_switch(self, None))
    # The Function get_link(self, None) outputs the list of links.
    #aparentemente este eh suficiente para identificar os links todos
    self.topo_raw_links = copy.copy(get_link(self, None))

    """
    Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
    """

    print(" \t" + "Current Links:")
    for l in self.topo_raw_links:
        print (" \t\t" + str(l))

    print(" \t" + "Current Switches:")
    for s in self.topo_raw_switches:
        print (" \t\t" + str(s))


    ## aqui atualizar o servidor gui

"""
    This event is fired when a switch leaves the topo. i.e. fails.
"""
@set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
def handler_switch_leave(self, ev):
    self.logger.info("Not tracking Switches, switch leaved.")