from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import dhcp
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import udp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import in_proto
from ryu.lib.packet import vlan
from ryu.lib import addrconv
from fp_constants import IPC, MACC
import ipaddress


  #dhcp protocol
        #client: dhcpdiscovery broadcast -> : dhcp server
        #Client: <- dhcpoffer unicast : dhcp server
        #client: dhcprequest broadcast -> :dhcp server
        #client: <- dhcpack unicast : dhcp server

### isso tem que ir para outro lugar 

_LIST_IPS = ['192.168.255.1', '192.168.255.2', '192.168.255.3', '192.168.255.4', '192.168.255.5', '192.168.255.6', '192.168.255.7',
            '192.168.255.8','192.168.255.9','192.168.255.11','192.168.255.12','192.168.255.13','192.168.255.14','192.168.255.15',
            '192.168.255.16','192.168.255.17','192.168.255.18','192.168.255.19','192.168.255.20','192.168.255.21' ]

# isso tem que ter o controle de qual switch conecta o host - mac-ip
mac_to_client_ip = {}

CONTROLLER_IP = IPC
CONTROLLER_MAC = MACC

#Isso cada switch/grupo de switches deve ter o seu
IP_NETWORK = '192.168.255.0'
IP_NETWORK_MASK = '255.255.255.0'
IP_DNS = '0.0.0.0'
dhcp_addr = CONTROLLER_IP
gw_addr = CONTROLLER_IP

def handle_dhcp(dhcpPkt, datapath, in_port):
    #verificar o tipo da mensagem
    msgType = ord(dhcpPkt.options.option_list[0].value)
    print(msgType)
    print(dhcpPkt.__dict__)
    if msgType == dhcp.DHCP_DISCOVER:
        # print( 'TIPO111111111111111')
        handle_dhcp_discovery(datapath, in_port, dhcpPkt)
    elif msgType == datapath.DHCP_REQUEST:
        # print( '22222222222222222222')
        handle_dhcp_request(dhcpPkt, datapath, in_port)
    else:
        pass

    #dhcp request
def handle_dhcp_discovery(controller_obj, datapath, in_port, dhcp_pkt):

    global mac_to_client_ip
    #melhor fazer isso no packetin msm
    # dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

    # #checar se eh um pacote dhcp 
    # if dhcp_pkt == None:
    #     return

    #identificador do switch
    # datapath.id

    print(dhcp_pkt.__dict__)

    ## montando dhcp_offer
    client_mac = dhcp_pkt.chaddr
    client_ip = dhcp_pkt.ciaddr
    xid = dhcp_pkt.xid
    flags = dhcp_pkt.flags
    hlen = dhcp_pkt.hlen
    hops = dhcp_pkt.hops
    giaddr = dhcp_pkt.giaddr
    yiaddr = _LIST_IPS.pop()
    sname = 'VM-CONTROLLER-001\0'

    #gateway addr os dois 
    dhcp_addr = CONTROLLER_IP
    gw_addr = CONTROLLER_IP
    broadcast_addr = '255.255.255.255'

    ip_network = IP_NETWORK

    dns_addr = '0.0.0.0'
    dhcp_hw_addr = CONTROLLER_MAC

    #obter um ip para o host
    # try:
        # Choose a IP form IP pool list
    client_ip_addr = str(_LIST_IPS.pop())

    mac_to_client_ip[client_mac] = client_ip_addr
    print('AAAAAMAC:%s' % (dhcp_pkt.chaddr))
    # except IndexError:
    #     self.logger.info("EMPTY IP POOL")
    #     return
        
    # send dhcp_offer message.
    dhcp_offer_msg_type = '\x02'
    controller_obj.logger.info("Send DHCP message type %s" %
                    (controller_obj.dhcp_msg_type_code[ord(dhcp_offer_msg_type)]))


    msg_option = dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                            value=dhcp_offer_msg_type)
        
    options = dhcp.options(option_list=[msg_option])
    hlen = len(addrconv.mac.text_to_bin(dhcp_pkt.chaddr))

    dhcp_pkt = dhcp.dhcp(hlen=hlen,
                        op=dhcp.DHCP_BOOT_REPLY,
                        chaddr=dhcp_pkt.chaddr,
                        yiaddr=client_ip_addr,
                        giaddr=dhcp_pkt.giaddr,
                        xid=dhcp_pkt.xid,
                        options=options)
        
    _send_dhcp_packet(datapath, dhcp_pkt, CONTROLLER_MAC, CONTROLLER_IP,  in_port)

    return
    
def handle_dhcp_request(controller_obj, dhcp_pkt, datapath, port):
    # send dhcp_ack message.
    dhcp_ack_msg_type = '\x05'
    controller_obj.logger.info("Send DHCP message type %s" %
                    (controller_obj.dhcp_msg_type_code[ord(dhcp_ack_msg_type)]))

    subnet_option = dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                                value=addrconv.ipv4.text_to_bin(IP_NETWORK_MASK))
    gw_option = dhcp.option(tag=dhcp.DHCP_GATEWAY_ADDR_OPT,
                            value=addrconv.ipv4.text_to_bin(gw_addr))
    dns_option = dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                             value=addrconv.ipv4.text_to_bin(IP_DNS))
    time_option = dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                              value='\xFF\xFF\xFF\xFF')
    msg_option = dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                             value=dhcp_ack_msg_type)
    id_option = dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                            value=addrconv.ipv4.text_to_bin(dhcp_addr))

    options = dhcp.options(option_list=[msg_option, id_option,
                           time_option, subnet_option,
                           gw_option, dns_option])
    hlen = len(addrconv.mac.text_to_bin(dhcp_pkt.chaddr))

    # Look up IP by using client mac address
    print('MAC:%s' % (dhcp_pkt.chaddr))

    #aqui mudei, o certo era apenas consultar pois ja deveria ter passado pelo discovery, mas caso nao tenha passado ainda (ja tenha ip) entao gerar outro ip
    client_ip_addr = '0.0.0.0'
    if dhcp_pkt.chaddr in mac_to_client_ip:
        client_ip_addr = mac_to_client_ip[dhcp_pkt.chaddr]
    else:
        #pronto, registrado
        client_ip_addr = str(_LIST_IPS.pop())
        mac_to_client_ip[dhcp_pkt.chaddr] = client_ip_addr

    dhcp_pkt = dhcp.dhcp(op=dhcp.DHCP_BOOT_REPLY,
                         hlen=hlen,
                         chaddr=dhcp_pkt.chaddr,
                         yiaddr=client_ip_addr,
                         giaddr=dhcp_pkt.giaddr,
                         xid=dhcp_pkt.xid,
                         options=options)

    _send_dhcp_packet(datapath, dhcp_pkt, CONTROLLER_MAC, CONTROLLER_IP, port)


def _send_dhcp_packet(controller_obj, datapath, dhcp_pkt, mac_src, ip_src, in_port):

    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet
                     (src=mac_src, dst="ff:ff:ff:ff:ff:ff"))
    pkt.add_protocol(ipv4.ipv4
                     (src=ip_src, dst="255.255.255.255", proto=17))
    pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
    pkt.add_protocol(dhcp_pkt)

    print(pkt)

    pkt.serialize()

    data = pkt.data
    actions = [datapath.ofproto_parser.OFPActionOutput(port=in_port)]
    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                          buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                          in_port=datapath.ofproto.OFPP_CONTROLLER,
                          actions=actions,
                          data=data)
    datapath.send_msg(out)



# IPv6 Neighbor Discovery Protocol defines 5 types of messages that use ICMPv6 encapsulation:

#     Router Solicitation (ICMPv6 type 133)
#     Router Advertisement (ICMPv6 type 134)
#     Neighbor Solicitation (ICMPv6 type 135)
#     Neighbor Advertisement (ICMPv6 type 136)
#     Redirect Message (ICMPv6 type 137)


# ipv6 icmpv6: https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_icmpv6.html?highlight=icmpv6
# implementação github: https://github.com/faucetsdn/faucet/commit/054871dc19fa5c21086fe9be93a60b4b15c718cd
# (base das funcoes) outra implementação: https://github.com/faucetsdn/faucet/blob/main/faucet/valve_packet.py
# nao entendi, tem alguma coisa que renomearam ryu para os-ken: https://opendev.org/openstack/os-ken/src/branch/master/os_ken

# string representation
HADDR_PATTERN = r'([0-9a-f]{2}:){5}[0-9a-f]{2}'

# MAC
DONTCARE = b'\x00' * 6
BROADCAST = b'\xff' * 6
DONTCARE_STR = '00:00:00:00:00:00'
BROADCAST_STR = 'ff:ff:ff:ff:ff:ff'
MULTICAST = 'fe:ff:ff:ff:ff:ff'
UNICAST = '01:00:00:00:00:00'


def build_pkt_header(vid, eth_src, eth_dst, dl_type):
    """Return an Ethernet packet header.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        dl_type (int): EtherType.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet with header.
    """
    pkt_header = packet.Packet()
    if vid is None:
        eth_header = ethernet.ethernet(eth_dst, eth_src, dl_type)
        pkt_header.add_protocol(eth_header)
    else:
        eth_header = ethernet.ethernet(eth_dst, eth_src, ether_types.ETH_TYPE_8021Q)
        pkt_header.add_protocol(eth_header)
        vlan_header = vlan.vlan(vid=vid, ethertype=dl_type)
        pkt_header.add_protocol(vlan_header)
    return pkt_header

def haddr_to_bin(string):
    """Parse mac address string in human readable format into
    internal representation"""
    try:
        return addrconv.mac.text_to_bin(string)
    except:
        raise ValueError

def is_multicast(addr):
    return bool(int(addr[0]) & 0x01)

def mac_addr_is_unicast(mac_addr):
    """Returns True if mac_addr is a unicast Ethernet address.

    Args:
        mac_addr (str): MAC address.
    Returns:
        bool: True if a unicast Ethernet address.
    """
    mac_bin = haddr_to_bin(mac_addr)
    if mac_bin == BROADCAST:
        return False
    return not is_multicast(mac_bin)

def ipv6_link_eth_mcast(dst_ip):
    """Return an Ethernet multicast address from an IPv6 address.

    See RFC 2464 section 7.

    Args:
        dst_ip (ipaddress.IPv6Address): IPv6 address.
    Returns:
        str: Ethernet multicast address.
    """
    mcast_mac_bytes = b"\x33\x33\xff" + dst_ip.packed[-3:]
    mcast_mac = ":".join(["%02X" % x for x in mcast_mac_bytes])
    return mcast_mac

def ipv6_solicited_node_from_ucast(ucast):
    """Return IPv6 solicited node multicast address from IPv6 unicast address.

    See RFC 3513 section 2.7.1.

    Args:
       ucast (ipaddress.IPv6Address): IPv6 unicast address.
    Returns:
       ipaddress.IPv6Address: IPv6 solicited node multicast address.
    """
    link_mcast_prefix = ipaddress.ip_interface("ff02::1:ff00:0/104")
    mcast_bytes = link_mcast_prefix.packed[:13] + ucast.packed[-3:]
    link_mcast = ipaddress.IPv6Address(mcast_bytes)
    return link_mcast

def nd_request(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return IPv6 neighbor discovery request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): Ethernet destination address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): requested IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    if mac_addr_is_unicast(eth_dst):
        nd_mac = eth_dst
        nd_ip = dst_ip
    else:
        nd_mac = ipv6_link_eth_mcast(dst_ip)
        nd_ip = ipv6_solicited_node_from_ucast(dst_ip)
    pkt = build_pkt_header(vid, eth_src, nd_mac, ether_types.ETH_TYPE_IPV6)
    ipv6_pkt = ipv6.ipv6(src=str(src_ip), dst=nd_ip, nxt=in_proto.IPPROTO_ICMPV6)
    pkt.add_protocol(ipv6_pkt)
    icmpv6_pkt = icmpv6.icmpv6(
        type_=icmpv6.ND_NEIGHBOR_SOLICIT,
        data=icmpv6.nd_neighbor(
            dst=dst_ip, option=icmpv6.nd_option_sla(hw_src=eth_src)
        ),
    )
    pkt.add_protocol(icmpv6_pkt)
    pkt.serialize()
    return pkt

#ipv6: Neighbor discovery protocol
def nd_advert(vid, eth_src, eth_dst, src_ip, dst_ip):
    IPV6_MAX_HOP_LIM= 255
    """Return IPv6 neighbor avertisement packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): destination IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether_types.ETH_TYPE_IPV6)
    ipv6_icmp6 = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=in_proto.IPPROTO_ICMPV6,
        hop_limit=IPV6_MAX_HOP_LIM,
    )
    pkt.add_protocol(ipv6_icmp6)
    icmpv6_nd_advert = icmpv6.icmpv6(
        type_=icmpv6.ND_NEIGHBOR_ADVERT,
        data=icmpv6.nd_neighbor(
            dst=src_ip, option=icmpv6.nd_option_tla(hw_src=eth_src), res=7
        ),
    )
    pkt.add_protocol(icmpv6_nd_advert)
    pkt.serialize()
    return pkt  

def router_advert(
    vid, eth_src, eth_dst, src_ip, dst_ip, vips, pi_flags=0x6
):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Return IPv6 ICMP Router Advert.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): dest Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        vips (list): prefixes (ipaddress.IPv6Address) to advertise.
        pi_flags (int): flags to set in prefix information field (default set A and L)
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 ICMP RA packet.
    """
    IPV6_RA_HOP_LIM = 255
    IPV6_MAX_HOP_LIM = 255
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether_types.ETH_TYPE_IPV6)
    ipv6_pkt = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=in_proto.IPPROTO_ICMPV6,
        hop_limit=IPV6_MAX_HOP_LIM,
    )
    pkt.add_protocol(ipv6_pkt)
    options = []
    for vip in vips:
        options.append(
            icmpv6.nd_option_pi(
                prefix=vip.network.network_address,
                pl=vip.network.prefixlen,
                res1=pi_flags,
                val_l=86400,
                pre_l=14400,
            )
        )
    options.append(icmpv6.nd_option_sla(hw_src=eth_src))
    # https://tools.ietf.org/html/rfc4861#section-4.6.2
    icmpv6_ra_pkt = icmpv6.icmpv6(
        type_=icmpv6.ND_ROUTER_ADVERT,
        data=icmpv6.nd_router_advert(rou_l=1800, ch_l=IPV6_RA_HOP_LIM, options=options),
    )
    pkt.add_protocol(icmpv6_ra_pkt)
    pkt.serialize()
    return pkt


##########################3 
# aqui o que encontrei sobre tratar esses pacotes:
# if 'arp_source_ip' in pkt and 'arp_target_ip' in pkt:
#         ethertype = ether.ETH_TYPE_ARP
#         layers.append(arp.arp(src_ip=pkt['arp_source_ip'], dst_ip=pkt['arp_target_ip']))
#     elif 'ipv6_src' in pkt and 'ipv6_dst' in pkt:
#         ethertype = ether.ETH_TYPE_IPV6
#         if 'neighbor_solicit_ip' in pkt:
#             layers.append(icmpv6.icmpv6(
#                 type_=icmpv6.ND_NEIGHBOR_SOLICIT,
#                 data=icmpv6.nd_neighbor(
#                     dst=pkt['neighbor_solicit_ip'],
#                     option=icmpv6.nd_option_sla(hw_src=pkt['eth_src']))))
#         elif 'echo_request_data' in pkt:
#             layers.append(icmpv6.icmpv6(
#                 type_=icmpv6.ICMPV6_ECHO_REQUEST,
#                 data=icmpv6.echo(id_=1, seq=1, data=pkt['echo_request_data'])))
#         layers.append(ipv6.ipv6(
#             src=pkt['ipv6_src'],
#             dst=pkt['ipv6_dst'],
#             nxt=inet.IPPROTO_ICMPV6))