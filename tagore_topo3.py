from mininet.util import irange,dumpNodeConnections
from mininet.node import Controller, RemoteController, OVSController
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
# bw_results={}
# def bwtest(a,b,net):
#         cl_bw,_=net.iperf((a,b))
#         bw_results[(a,b)]=cl_bw
# 	return 

def custtopo():
        custnet=Mininet(controller=RemoteController)
        info('***Adding controller***\n')
        c0=custnet.addController(name='c0',controller=RemoteController,ip='127.0.0.1',protocol='tcp',port=6633)
        info('***Adding switches\n')
        s1=custnet.addSwitch('s1')
        s2=custnet.addSwitch('s2')
        s3=custnet.addSwitch('s3')
        s4=custnet.addSwitch('s4')
        s5=custnet.addSwitch('s5')
        s6=custnet.addSwitch('s6')
        info('***Adding hosts\n')
        h1=custnet.addHost('h1',ip='10.0.0.1/24', mac="00:00:00:00:00:01")
        h2=custnet.addHost('h2',ip='10.0.0.2/24', mac="00:00:00:00:00:02")
        h4=custnet.addHost('h4',ip='10.0.0.4/24', mac="00:00:00:00:00:04")
        h5=custnet.addHost('h5',ip='10.0.0.5/24', mac="00:00:00:00:00:05")
        h6=custnet.addHost('h6',ip='10.0.0.6/24', mac="00:00:00:00:00:06")
        
        info('***creating LINKS****\n')
        custnet.addLink(h1,s1)
        custnet.addLink(h2,s2)
        custnet.addLink(h4,s4)
        custnet.addLink(h5,s5)
        custnet.addLink(h6,s6)
        custnet.addLink(s1,s2,cls=TCLink,delay='10ms')
        custnet.addLink(s1,s5,cls=TCLink,delay='15ms')
        custnet.addLink(s1,s3,cls=TCLink,delay='10ms') 
        custnet.addLink(s2,s3,cls=TCLink,delay='15ms')
        custnet.addLink(s2,s4,cls=TCLink,delay='15ms')
        custnet.addLink(s3,s4,cls=TCLink,delay='5ms')
        custnet.addLink(s5,s6,cls=TCLink,delay='15ms')
        custnet.addLink(s6,s4,cls=TCLink,delay='10ms')

        info('***StartingNetwork***\n')
        custnet.start()
        info("***Dumping host connections***\n")
        dumpNodeConnections(custnet.hosts)
   	#info('***Testing  Network Connectivity***\n')
        #custnet.pingAll()
        CLI(custnet)
        info('****STOPPING NETWORK**\n')
        custnet.stop()
if __name__=='__main__':
        setLogLevel('info')
        custtopo()

