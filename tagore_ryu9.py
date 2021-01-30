

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import *
from ryu.topology import event
from os import *
from ryu.lib.mac import haddr_to_bin
import networkx as nx
from subprocess import Popen, PIPE, STDOUT
import subprocess
import os.path
from ryu.lib.mac import haddr_to_bin
from thread import start_new_thread

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.net=nx.Graph()
	self.g=nx.DiGraph()
	self.nodes={}
	self.all_switches=[]
	self.all_links=[]
	#self.links={}
	self.flag = 0
	self.count=0
        self.delay   = {(1, 2): 10, (6, 4): 10,(4,6):10, (3, 2): 15, (1, 3): 10, (3, 1): 10, (2, 1): 10, (1, 5): 15, (2, 3): 15, (4, 3): 5, (5, 1): 15, (4, 2): 15, (3, 4): 5, (2, 4): 15, (6, 5): 15,(5,6):15}
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
 
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    def add_flow1(self, datapath,in_port,dst,actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #print("ADDRESS FORMAT ERROR LNE:"+str(type(dst))+str(dst))   
	match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst)
	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]	
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, cookie=0,command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,priority=ofproto.OFP_DEFAULT_PRIORITY,flags=ofproto.OFPFF_SEND_FLOW_REM,instructions=inst)
	datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
	if src not in self.net:
            	self.net.add_node(src)
		self.g.add_node(src)
            	self.net.add_edge(src,dpid)
		self.g.add_edge(src,dpid,{'port':in_port})
            	self.net.add_edge(dpid,src)
		self.g.add_edge(dpid,src,{'port':in_port})
	if dst in self.net:
	    path=nx.dijkstra_path(self.net,src,dst)
	    print("PACKET SRC:"+str(src)+"->DEST:"+str(dst))
	    print("PATH TAKEN:"+str(path)+"\n")   
            next=path[path.index(dpid)+1]
	    #print("NEXT"+str(next))
            #print("PRINT NEXT NODE"+str(self.g[dpid][next]))
	    out_port=self.g[dpid][next]['port']
	else:
	    self.count=self.count+1
            out_port = ofproto.OFPP_FLOOD
	actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
	    self.add_flow1(datapath,in_port,dst,actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(event.EventLinkAdd)
    def get_link(self,ev):
        links_list = get_link(self)
        self.all_links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
	#print(self.all_links)
	self.flag=self.flag+1
	if self.flag==15:
		print("Network Information:\n")
		print("LINKS:")
		print(self.all_links)
		print("LINKS DELAY")
		print(self.delay)
		print("SWITCHES/NODES")
		print(self.all_switches)

	# ADDING EDGES BETWEEN NODES
	for link in self.all_links:
		a,b,_=link
		self.net.add_edge(a,b,weight=int(self.delay[(a,b)]))
	self.g.add_edges_from(self.all_links)
	#print("EDGES:"+str(self.net.edges()))

	##
    @set_ev_cls(event.EventSwitchEnter)
    def get_switch(self,ev):
        switch_list = get_switch(self)
        self.all_switches = [switch.dp.id for switch in switch_list]
	self.net.add_nodes_from(self.all_switches)
	self.g.add_nodes_from(self.all_switches)


