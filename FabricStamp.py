from netaddr import *
import yaml
import re
from jinja2 import Template

### YAML file
yamlfile = 'example.yaml'

### Device Roles
evpn_roles = ['Spine', 'Compute Leaf', 'Service Leaf', 'Storage Leaf']

bgp_only = ['Border Leaf']

### Device Templates

## MLAG Template
mlagconfig = Template("""\
vlan {{ vlanid }}
   name MLAG
   trunk group MLAG
interface vlan {{ vlanid }}
   no autostate
   description MLAG
   ip address {{ IP }}
mlag configuration
   domain-id {{ MLAGDomain }}
   local-interface vlan{{ vlanid }}
   peer-address {{ peerip }}
   peer-link Port-Channel{{ mlag_portchannel }}
   reload-delay mlag 420
   reload-delay non-mlag 360
   reload-delay mode lacp standby\n
""")

## BGP Non-EVPN Template
bgpconfig = Template("""\
router bgp {{ bgpas }}
   bgp asn notation asdot
   maximum-paths 4 ecmp 4
   router-id {{ rtrid }}
   update wait-for-convergence
   update wait-install
   distance bgp 20 200 200\n
""")

bgp_neighbor = Template("""\
   neighbor {{ neighborip }} remote-as {{ neighboras }}
   neighbor {{ neighborip }} description {{ neighborname }}
   neighbor {{ neighborip }} send-community standard\n
""")
## iBGP MLAG Template
ibgp_bgpconfig = Template("""\
   neighbor iBGP_MLAG peer-group
   neighbor iBGP_MLAG remote-as {{ bgpas }}
   neighbor iBGP_MLAG next-hop-self
   neighbor iBGP_MLAG fall-over bfd
   neighbor {{ mlag_neighbor }} peer-group iBGP_MLAG\n
""")

## BGP EVPN Template
evpn_bgpconfig = Template("""\
router bgp {{ bgpas }}
   bgp asn notation asdot
   maximum-paths 4 ecmp 4
   router-id {{ rtrid }}
   update wait-for-convergence
   update wait-install
   distance bgp 20 200 200
   neighbor UNDERLAY peer-group
   neighbor UNDERLAY send-community standard
   neighbor OVERLAY peer-group
   neighbor OVERLAY update-source Loopback0
   neighbor OVERLAY send-community extended
   neighbor OVERLAY maximum-routes 0
   neighbor OVERLAY ebgp-multihop 5\n
""")

evpn_bgp_neighbor = Template("""\
   neighbor {{ neighborip }} peer-group UNDERLAY
   neighbor {{ neighborip }} remote-as {{ neighboras }}
   neighbor {{ neighborip }} description {{ neighborname }}\n
""")

## EVPN Leaf Template
evpnleaf = Template("""\
   neighbor {{ spineip }} peer-group OVERLAY
   neighbor {{ spineip }} remote-as {{ spine_asn }}
   neighbor {{ spineip }} description {{ spine_Lo0 }}\n
""")

evpn_afv4_suffix = Template("""\
   address-family ipv4
      no neighbor OVERLAY activate
      neighbor UNDERLAY activate\n
""")
evpn_afevpn_suffix = Template("""\
   address-family evpn
      neighbor OVERLAY activate\n
""")

### Functions
def bgp_peer(interfaceIP):
    ## Function to determine alternate side IP in /31.
    ### Assumes /31 for Routed Links ###
    ip = IPNetwork(interfaceIP)
    if ip.ip == ip.network:
        #print 'Is lower'
        peer_ip = str(IPAddress(ip.last))
    else:
        #print 'Is higher'
        peer_ip = str(IPAddress(ip.first))
    return peer_ip

def mlag_peer(interfaceIP):
    ## Function to determine alternate side IP in /30.
    ### Assumes /30 for MLAG Subnet ###
    ip = IPNetwork(interfaceIP)
    if int(ip.ip) == int(ip.network) + 1:
        #print 'Is lower'
        peer_ip = str(IPAddress(ip.first + 2))
    else:
        #print 'Is higher'
        peer_ip = str(IPAddress(ip.first + 1))
    return peer_ip

### Main Script
def main():
    ### OPEN YAML file with device details.
    with open(yamlfile, 'r') as f:
        doc = yaml.load(f)
    spines = []
    leaves = []
    for switch in doc.keys():
        if doc[switch]['description'] in evpn_roles:
            if doc[switch]['description'] == 'Spine':
                spines.append(switch)
            else:
                leaves.append(switch)
           
    ethernetport = re.compile('^E[0-9]{1,2}')
    routedlinks = []
    for item in doc.keys():
        device_role = doc[item]['description']
        with open(item+'.txt', 'w') as f:
            f.write('hostname %s\n' % item)
            if 'Ma1' in doc[item].keys():
                f.write('interface Management1\n   ip address %s\n' % doc[item]['Ma1'])
            if 'Lo0' in doc[item].keys():
                f.write( 'interface Loopback0\n   ip address %s\n' % doc[item]['Lo0'])
            if 'Lo100' in doc[item].keys():
                f.write( 'interface Loopback100\n   ip address %s\n' % doc[item]['Lo100'])
            for key in doc[item].keys():
                if ethernetport.match(key):
                    if doc[item][key]['portconfig'] == 'MLAGTrunk':
                        f.write( 'interface Ethernet%s\n' % key.strip('E') +\
                        '   description MLAG\n' +\
                        '   switchport mode trunk\n   switchport trunk group MLAG\n' +\
                        '   channel-group %s mode active\n' % doc[item]['MLAG']['PortChannel'])
                    else:
                        routedlinks.append(key)
                        f.write( 'interface Ethernet%s\n' % key.strip('E') +\
                        '   no switchport\n   mtu 9214\n'+\
                        '   description %s\n   ip address %s\n' % ( doc[item][key]['desc'],
                        doc[item][key]['portconfig']))
            if 'MLAG' in doc[item].keys():
                mlag = doc[item]['MLAG']
                f.write(mlagconfig.render(vlanid=mlag['VLAN'], IP=mlag['IP'],
                MLAGDomain=mlag['Domain'], peerip=mlag_peer(mlag['IP']),
                mlag_portchannel=mlag['PortChannel']))
            if 'BGP-AS' in doc[item].keys():
                bgpas = doc[item]['BGP-AS']
                rtrid = IPAddress(IPNetwork(doc[item]['Lo0']))
                if device_role in evpn_roles:
                    f.write(evpn_bgpconfig.render(bgpas=bgpas,rtrid=rtrid))
                if device_role in bgp_only:
                    f.write(bgpconfig.render(bgpas=bgpas,rtrid=rtrid))
                if 'MLAG' in doc[item].keys():
                    mlag = doc[item]['MLAG']
                    f.write(ibgp_bgpconfig.render(bgpas=bgpas,mlag_neighbor=mlag_peer(mlag['IP'])))
                for interface in routedlinks:
                    intfip = doc[item][interface]['portconfig']
                    neighborip = bgp_peer(intfip)
                    neighborname = doc[item][interface]['desc']
                    neighboras = doc[str(neighborname)]['BGP-AS']
                    if device_role in evpn_roles:
                        f.write(evpn_bgp_neighbor.render(neighborip=neighborip,
                                neighboras=neighboras, neighborname=neighborname))
                    if device_role in bgp_only:
                        f.write(bgp_neighbor.render(neighborip=neighborip,
                                neighboras=neighboras, neighborname=neighborname))
                if device_role in bgp_only:
                    f.write('   address-family ipv4\n')
                    if 'Lo0' in doc[item].keys():
                        f.write('      network '+doc[item]['Lo0']+ '\n')
                    if 'Lo100' in doc[item].keys():
                        f.write('      network '+doc[item]['Lo100']+'\n')
                if device_role in evpn_roles:
                  if device_role == 'Spine':
                    for leaf in leaves:
                        leafip = doc[leaf]['Lo0'].replace('/32','')
                        leaf_asn = doc[leaf]['BGP-AS']
                        f.write(evpnleaf.render(spineip=leafip,
                                spine_asn=leaf_asn, spine_Lo0=leaf+'Lo0'))
                  else:
                    for spine in spines:
                        spineip = doc[spine]['Lo0'].replace('/32','')
                        spine_asn = doc[spine]['BGP-AS']
                        f.write(evpnleaf.render(spineip=spineip,
                                spine_asn=spine_asn, spine_Lo0=spine+'Lo0'))
                    f.write(evpn_afv4_suffix.render())
                    if 'Lo0' in doc[item].keys():
                        f.write('      network '+doc[item]['Lo0']+ '\n')
                    if 'Lo100' in doc[item].keys():
                        f.write('      network '+doc[item]['Lo100']+'\n')
                    f.write(evpn_afevpn_suffix.render())
                routedlinks = []

if __name__ == "__main__":
  main()
