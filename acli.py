################################################################################
#                             _    ____ _     ___                              #
#                            / \  / ___| |   |   |                             #
#                           / _ \| |   | |    | |                              #
#                          / ___ \ |___| |___ | |                              #
#                         /_/   \_\____|_____|___|                             #
#                                                                              #
#                                                                              #
################################################################################
#                                                                              #
# Copyright 2019 Evolvere Technologies Ltd                                     #
#                                                                              #
#    Licensed under the Apache License, Version 2.0 (the "License"); you may   #
#    not use this file except in compliance with the License. You may obtain   #
#    a copy of the License at                                                  #
#                                                                              #
#         http://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                              #
#    Unless required by applicable law or agreed to in writing, software       #
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT #
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the  #
#    License for the specific language governing permissions and limitations   #
#    under the License.                                                        #
#                                                                              #
################################################################################

import requests
import re
import sys
import datetime
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning
from cmd import Cmd
from operator import attrgetter
from getpass import getpass
from prettytable import PrettyTable

try:
    from settings.aci_settings import FABRICS
except:
    sys.exit('ERROR: Missing or incorrect aci_settings.py file.')

SHOW_CMDS = ['epg', 'interface', 'vlan', 'snapshot']
SHOW_EPG_CMDS = ['NAME', 'all|ALL']
SHOW_VLAN_CMDS = ['pools', '<vlan_id>']
SHOW_INTF_CMDS = ['<node>', ]
CONFIG_CMDS = ['snapshot', ]
CONFIG_SNAPSHOT = ['<snapshot_id>', 'new']

class Apic(Cmd):
    def __init__(self):
        Cmd.__init__(self)
        import readline
        readline.set_completer_delims(' ')
        if 'libedit' in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
        self.can_connect = ''
        self.cookie = None
        self.headers = {'content-type': "application/json", 'cache-control': "no-cache"}
        self.fabric = []
        self.snapshots = []
        self.leafs = []
        self.epg_names = []
        self.vlan_pools = []
        self.idict = {}
        self.epgs = []
        self.refresh_time_epoch = 0
        self.username = ''
        self.password = ''
        self.address = ''
        self.session = requests.Session()
        self.apic_address = ''

    def do_login(self, args):
        """Usage: login [FABRIC_NAME]"""
        if self.can_connect:
            try:
                self.disconnect()
            except:
                pass

        self.can_connect = ''

        if len(args) == 0:
            print "Usage: login [FABRIC_NAME]"    
        else:
            parameters = args.split()
            if parameters[0] in FABRICS.keys():
                self.fabric = FABRICS[parameters[0]]
                self.username = ''
                self.password = ''
                for apic_credentials in self.fabric:
                    if not apic_credentials['username'] or not apic_credentials['password']:
                        if not self.username and not self.password:
                            self.username = raw_input('Enter username: ')
                            self.password = getpass()
                    else:
                        self.username = apic_credentials['username']
                        self.password = apic_credentials['password']

                    self.address = apic_credentials['address']
                    try:
                        self.connect()
                        self.can_connect = parameters[0]
                        print 'Established connection to APIC in', self.can_connect
                        self.prompt = 'ACLI({})>'.format(self.can_connect)
                        break
                    except Exception as error:
                        print 'ERROR', str(error)
                        pass
                if not self.can_connect:
                    print 'Cannot connect to APIC in', parameters[0]

    def do_config(self, args):
        """
        Performs basic admin configuration tasks for Cisco ACI
        Usage:
        config snapshot new | <snapshot_id>
        """
        if self.can_connect:
            if len(args) == 0:
                print "Usage: config snapshot <id>. "
            elif 'snapshot' in args:
                parameters = args.split()
                if (len(parameters) == 2) and ('new' in parameters[1]):
                    description = raw_input('Enter description for the snapshot: ')
                    status = self.create_snapshot(description)
                    if status[0] == 0:
                        print 'Snapshot has been successfully created'
                    else:
                        print 'ERROR: failed to create new snapshot'

                elif (len(parameters) == 2) and (int(parameters[1]) + 1 <= len(self.snapshots)):
                    snapshot_id = parameters[1]
                    description = raw_input('Enter new description for the snapshot: ')
                    status = self.update_snapshot_description(snapshot_id, description)
                    if status[0] == 0:
                        print 'Description has been successfully updated for snapshot ID', snapshot_id
                    else:
                        print 'ERROR: failed to update description for snapshot ID', snapshot_id
                else:
                    print 'Usage: config snapshot <id>.'
        else:
            print 'Login to a Fabric'
        return

    def do_show(self, args):
        """
        Retrieves information from Cisco ACI
        Usage:
        show epg [<epg_name>]
        show interface [<node>] [<leaf_interface, i.e. 1/10>]
        show vlan <vlan_id> | pool
        show snapshot
        """
        if self.can_connect:
            if len(args) == 0:
                print "Usage: show epg, show interfaces or show vlan."
            elif 'epg'in args:
                parameters = args.split()
                if len(parameters) >= 2:
                    if parameters[1] in self.epg_names:
                        epg = parameters[1]
                    else:
                        epg='ALL'
                else:
                    epg='ALL'
                self.get_epg_data(epg)
                self.get_interface_data()
                self.print_epgs()
            elif 'interface' in args:
                parameters = args.split()
                if len(parameters) >= 2:
                    if (len(parameters) == 2) and (parameters[1] in self.leafs):
                        self.get_interface_data(parameters[1])
                        self.print_interface()
                    elif (len(parameters) == 3) and (parameters[1] in self.leafs):
                        self.get_interface_data(parameters[1])
                        self.get_epg_data(epg='ALL')
                        try:
                            node = parameters[1]
                            port = parameters[2]
                            idx = 0
                            if len(port.split('/')) == 3:
                                idx = int(node) * 1000000 + int(port.split('/')[0]) * 1000 + \
                                      int(port.split('/')[1]) * 100 + int(port.split('/')[2])

                            elif len(port.split('/')) == 2:
                                idx = int(node) * 1000000 + int(0) * 1000 + \
                                      int(port.split('/')[0]) * 100 + int(port.split('/')[1])

                            if idx in self.idict:
                                self.print_interface_details(idx)
                            else:
                                print 'ERROR: Interface is not present on the Node or not a LEAF port', parameters[1]
                        except Exception as error:
                            print 'ERROR: ', str(error)

                    else:
                        print 'ERROR: Incorrect Node or Interface'
                else:
                    self.get_interface_data()
                    self.print_interface()
            elif 'snapshot' in args:
                self.print_snapshot()
            elif 'vlan' in args:
                parameters = args.split()
                if len(parameters) == 2 and 'pool' not in parameters[1]:
                    try:
                       vlan_id = int(parameters[1])
                       if (vlan_id >= 1) and (vlan_id <= 4096):
                            self.get_epg_data('ALL')
                            self.get_vlan_pool()
                            self.vlan_usage(vlan_id)
                       else:
                           print 'VLAN needs to be 1-4096'
                    except Exception as error:
                       print str(error)
                elif len(parameters) == 2 and 'pool' in parameters[1]:
                    self.get_vlan_pool()
                    self.print_vlan_pool()
                else:
                    print 'Usage: show vlan pools or show vlan [VLAN]'
        else:
            print 'Login to a Fabric'
        return

    def complete_config(self, text, line, begidx, endidx):

        if begidx == 7:
            if text:
                return [i for i in CONFIG_CMDS if i.startswith(text)]
            else:
                return CONFIG_CMDS

        if begidx == 16 and 'snapshot' in line:
            if text:
                return [i for i in CONFIG_SNAPSHOT if i.startswith(text)]
            else:
                return CONFIG_SNAPSHOT

    def complete_show(self, text, line, begidx, endidx):

        if begidx == 5:
            if text:
                return [i for i in SHOW_CMDS if i.startswith(text)]
            else:
                return SHOW_CMDS

        if begidx == 9 and 'epg' in line:
            if text:
                return [i for i in self.epg_names if i.startswith(text)]
            else:
                return self.epg_names
        
        if begidx == 10 and 'vlan' in line:
            if text:
                return [i for i in SHOW_VLAN_CMDS if i.startswith(text)]
            else:
                return SHOW_VLAN_CMDS

        if begidx == 15 and 'interface' in line:
            if text:
                return [i for i in self.leafs if i.startswith(text)]
            else:
                return self.leafs

    def complete_login(self, text, line, begidx, endidx):
        if begidx == 6 and 'login' in line:
            if text:
                return [i for i in FABRICS if i.startswith(text)]
            else:
                return FABRICS.keys()

    def do_quit(self, args):
        """Quits the program."""
        print "Leaving ACLI."
        self.disconnect()
        raise SystemExit

    def do_exit(self, args):
        """Quits the program."""
        print "Leaving ACLI."
        self.disconnect()
        raise SystemExit


    def emptyline(self):
        pass

    def connect(self):
        apic_user = self.username
        apic_password = self.password
        apic_address = self.address
        uri = "https://{0}/api/aaaLogin.json".format(apic_address)
        payload = {'aaaUser': {'attributes': {'name': apic_user, 'pwd': apic_password}}}
        response = self.session.post(uri, data=json.dumps(payload), headers=self.headers, verify=False)
        self.cookie = {'APIC-cookie': response.cookies['APIC-cookie']}
        self.apic_address = apic_address

        self.refresh_time_epoch = int(datetime.datetime.now().strftime('%s'))
        self.collect_epgs()
        self.collect_leafs()

    def refresh_connection(self, timeout=90):
        try:
            current_time_epoch = int(datetime.datetime.now().strftime('%s'))

            if current_time_epoch - self.refresh_time_epoch >= timeout:
                self.connect()
            else:
                self.refresh_time_epoch = current_time_epoch

            return [0, ]

        except:
            print 'Lost connection to Fabric', self.can_connect
            self.can_connect = ''
            apic.prompt = 'ACLI()>'
            return [1, ]

    def disconnect(self):
        try:
            self.session.close()
        except:
            pass
        apic.prompt = 'ACLI()>'

    def collect_epgs(self):
        uri = 'https://{0}/api/class/fvAEPg.json?'.format(self.apic_address)
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        self.epg_names = []
        for epg in response['imdata']:
            self.epg_names.append(epg['fvAEPg']['attributes']['name'])

    def collect_leafs(self):
        uri = 'https://{0}/api/class/fabricNode.json?'.format(self.apic_address)
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        self.leafs = []
        for node in response['imdata']:
            if node['fabricNode']['attributes']['role'] == 'leaf':
                self.leafs.append(node['fabricNode']['attributes']['id'])
    
    def collect_snapshots(self):

        result = self.refresh_connection()

        if result[0] == 1:
            return

        self.snapshots = []
        uri = 'https://{0}/api/class/configSnapshot.json?'.format(self.apic_address)
        self.snapshots = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()['imdata']

        return    

    def create_snapshot(self, description):

        result = self.refresh_connection()

        if result[0] == 1:
            return

        config_payload = {'configExportP': {'attributes' : {'name': 'defaultOneTime', 'adminSt': 'triggered',
                                                            'snapshot': 'true', 'descr': description}}}
        uri = 'https://{0}/api/node/mo/uni/fabric/configexp-defaultOneTime.json'.format(self.apic_address)

        response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie,
                                     verify=False)

        if response.status_code == 200:
            return [0, ]
        else:
            return [1, ]

    def update_snapshot_description(self, snapshot_id, description):

        result = self.refresh_connection()

        if result[0] == 1:
            return

        snapshot = self.snapshots[int(snapshot_id)]
        snapshot_dn = snapshot['configSnapshot']['attributes']['dn']
        uri = 'https://{0}/api/mo/{1}.json'.format(self.apic_address, snapshot_dn)

        config_payload = {'configSnapshot': {'attributes': {'descr': description}}}

        response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie,
                                     verify=False)
        if response.status_code == 200:
            return [0, ]
        else:
            return [1, ]
    
    def get_epg_data(self, epg):

        result = self.refresh_connection()

        if result[0] == 1:
           return

        self.epgs = []
        if epg:
            if epg == 'ALL':
                uri = 'https://{0}/api/class/fvAEPg.json?rsp-subtree=children'\
                                             '&rsp-subtree-class=fvRsPathAtt,fvRsBd,tagInst'.format(self.apic_address)

            else:
                uri = 'https://{0}/api/class/fvAEPg.json?rsp-subtree=children'\
                                             '&rsp-subtree-class=fvRsPathAtt,fvRsBd,tagInst'\
                                             '&query-target-filter=eq(fvAEPg.name, "{1}")'.format(self.apic_address,
                                                                                                  epg)

            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()

            for epg in response['imdata']:
                paths = []
                tags = []
                name = epg['fvAEPg']['attributes']['name']
                tn = epg['fvAEPg']['attributes']['dn'].split('/')[1].replace('tn-', '')
                ap = epg['fvAEPg']['attributes']['dn'].split('/')[2].replace('ap-', '')
                if 'children' in epg['fvAEPg']:
                    for child in epg['fvAEPg']['children']:
                        if 'fvRsPathAtt' in child:
                            encap = child['fvRsPathAtt']['attributes']['encap'].replace('vlan-', '')
                            t_dn = child['fvRsPathAtt']['attributes']['tDn']
                            match = re.findall('\[.*\]', t_dn)
                            pathep = match[0].strip('[]')

                            if 'protpaths' in t_dn:
                                protpaths = t_dn.split('/')[2]
                                vpc = t_dn.split('/')[-1].split('[')[-1][:-1]
                                path_dict = {'vpc': vpc, 'protpaths': protpaths, 'encap': encap, 'idx': 0}
                                paths.append(path_dict)

                            elif '/paths' in t_dn:

                                if 'eth' in pathep and not 'extpaths-' in t_dn:
                                    intf_id = pathep.replace('eth', '')
                                    node = t_dn.split('/')[2].replace('paths-', '')
                                    fex = 0
                                    idx = int(node)*1000000 + int(fex)*1000 + int(str(intf_id).split('/')[0])*100 +\
                                        int(str(intf_id).split('/')[-1])
                                    path_dict = {'idx': idx, 'node': node, 'intf_id': intf_id, 'encap': encap}
                                    paths.append(path_dict)

                                elif 'eth' in pathep and 'extpaths-' in t_dn:
                                    intf_id = pathep.replace('eth', '')
                                    node = t_dn.split('/')[2].replace('paths-', '')
                                    fex = t_dn.split('/')[3].replace('extpaths-', '')
                                    idx = int(node)*1000000 + int(fex)*1000 + int(str(intf_id).split('/')[0])*100 +\
                                        int(str(intf_id).split('/')[-1])
                                    path_dict = {'idx': idx, 'node': node, 'intf_id': intf_id, 'encap': encap}
                                    paths.append(path_dict)

                                elif not 'eth' in pathep:
                                    policy_grp = pathep
                                    node = t_dn.split('/')[2].replace('paths-', '')
                                    path_dict = {'idx': 0, 'node': node, 'pc': policy_grp, 'encap': encap}
                                    paths.append(path_dict)

                        elif 'tagInst' in child:
                            tags.append(child['tagInst']['attributes']['name'])

                        elif 'fvRsBd' in child:
                            t_dn = child['fvRsBd']['attributes']['tDn']
                            bd_tn = t_dn.split('/')[1].replace('tn-', '')
                            bd = t_dn.split('/')[2].replace('BD=', '')
                            bd_full = bd_tn + '/' + bd

                paths_sorted = sorted(paths, key=lambda k: k['idx'])
                epg_dict = {'name': name, 'tn': tn, 'ap': ap, 'bd': bd_full, 'paths': paths_sorted, 'tags': tags}
                self.epgs.append(epg_dict)
                

    def get_interface_data(self, target_node=''):
        # Initialize self.idict
        self.idict = {}

        # Populates self.idict:
        #
        # { "104146": {
        #              "descr": "",
        #              "intf_id": "1/46",
        #              "node": "node-104",
        #              "operDuplex": "full",
        #              "operSpeed": "10G",
        #              "operSt": "up",
        #              "pod": "1",
        #              "policy_group": "10G-ACCESS-EXISTING-LAB",
        #              "portT": "leaf",
        #              "port_sr_name": "Nutanix8",
        #              "usage": "epg,infra"
        #             },
        # }

        port_to_switch_prof_map = {}
        # format:
        # {'UCS-103-104-FI-B-IFSELECTOR': ['SP-UCS-103-104-FI-B'],
        #  'LF1_ACCESS': ['LF1_SPR']}
        #
        uri = "https://{0}/api/class/infraRtAccPortP.json".format(self.apic_address)
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        for mo in response['imdata']:
            mo_class = mo.keys()[0]
            sw_sel = mo[mo_class]['attributes']['tDn'].split('/')[2].replace('nprof-', '')
            int_sel = mo[mo_class]['attributes']['dn'].split('/')[2].replace('accportprof-', '')
            port_to_switch_prof_map.setdefault(int_sel, []).append(sw_sel)

        fex_to_interface_profile_map = {}
        uri = "https://{0}/api/node/class/infraFexBndlGrp.json".format(self.apic_address)
        subtree = 'children'
        subtreeClassFilter = 'infraRtAccBaseGrp'
        options = '?rsp-subtree={0}&rsp-subtree-class={1}'.format(subtree, subtreeClassFilter)
        uri += options
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        if response['imdata']:
            for item in response['imdata']:
                if 'children' in item['infraFexBndlGrp']:
                    fex_profile = item['infraFexBndlGrp']['attributes']['name']
                    rt_base_group = item['infraFexBndlGrp']['children'][0]['infraRtAccBaseGrp']['attributes']
                    interface_profile = rt_base_group['tDn'].split('/')[2].replace('accportprof-', '')
                    fex_to_interface_profile_map[fex_profile] = interface_profile
        switch_prof_leafs = {}
        # format:
        # {'SP-UCS-103-104-FI-B': [103, 104],
        #  'LF1_SPR': [101]]
        #
        uri = "https://{0}/api/class/infraNodeBlk.json".format(self.apic_address)
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        for mo in response['imdata']:
            mo_class = mo.keys()[0]
            sw_sel = mo[mo_class]['attributes']['dn'].split('/')[2].replace('nprof-', '')
            from_ = int(mo[mo_class]['attributes']['from_'])
            to_ = int(mo[mo_class]['attributes']['to_']) + 1
            for node in range(from_, to_):
                switch_prof_leafs.setdefault(sw_sel, []).append(node)

        access_port_selectors = {}
        # format:
        # UCS-103-104-FI-B-IFSELECTOR': [{'interfaces': ['1/48'], 'policy_group': u'PG-UCS2-FI-B', 'hport_name': u'UCS-FI-B-PORT2'}],
        #
        uri = "https://{0}/api/class/infraHPortS.json".format(self.apic_address)
        options = '?query-target=subtree'
        uri += options
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        for mo in response['imdata']:
            mo_class = mo.keys()[0]
            # Relies on ACI returning objects in PortBlk, RsAccBaseGrp, HPortS order
            if 'accportprof-' in mo[mo_class]['attributes']['dn']:
                isl = mo[mo_class]['attributes']['dn'].split('/')[2].replace('accportprof-', '')
            elif 'fexprof-' in mo[mo_class]['attributes']['dn']:
                fex_prof = mo[mo_class]['attributes']['dn'].split('/')[2].replace('fexprof-', '')
                if fex_prof in fex_to_interface_profile_map:
                    isl = fex_to_interface_profile_map[fex_prof]

            if mo_class == 'infraPortBlk':
                fromPort = int(mo[mo_class]['attributes']['fromPort'])
                toPort = int(mo[mo_class]['attributes']['toPort']) + 1
                interfaces = []
                for intf in range(fromPort, toPort):
                    intf_name = '1/' + str(intf)
                    interfaces.append(intf_name)

            if mo_class == 'infraRsAccBaseGrp':
                if 'fexbundle' in mo[mo_class]['attributes']['tDn']:
                    pol_grp = mo[mo_class]['attributes']['tDn'].split('/')[3].replace('fexbundle-', '')
                else:
                    pol_grp = mo[mo_class]['attributes']['tDn'].split('-', 1)[-1]
                if 'fexprof-' in mo[mo_class]['attributes']['dn']:
                    fex = mo[mo_class]['attributes']['fexId']
                else:
                    fex = '0'

            if mo_class == 'infraHPortS':
                hport_name = mo[mo_class]['attributes']['name']
                access_port_selectors.setdefault(isl, []).append({'fex': fex, 'hport_name': hport_name, 'policy_group': pol_grp, 'interfaces': interfaces})

        port_profiles = {}
        # Format:
        # {104148: {'port_sr_name': u'UCS-FI-B-PORT2', 'policy_group': u'PG-UCS2-FI-B'},  }
        #
        for port_selector in access_port_selectors:
            if port_selector in port_to_switch_prof_map:
                for port_selector_item in access_port_selectors[port_selector]:
                    policy_group = port_selector_item['policy_group']
                    port_sr_name = port_selector_item['hport_name']
                    fex = port_selector_item['fex']
                    nodes = []
                    for sw_sel in port_to_switch_prof_map[port_selector]:
                        if sw_sel in switch_prof_leafs:
                            for node in switch_prof_leafs[sw_sel]:
                                nodes.append(node)
                    if nodes:
                        for node in set(nodes):
                            for intf in set(port_selector_item['interfaces']):
                                hport_dict = {}
                                key = int(node)*1000000 + int(fex)*1000 + int(intf.split('/')[0])*100 + int(intf.split('/')[-1])
                                hport_dict['policy_group'] = policy_group
                                hport_dict['port_sr_name'] = port_sr_name
                                port_profiles[key] = hport_dict

        leaf_nodes = []
        # format:
        # [101, 102, 103, 104]
        #
        uri = "https://{0}/api/class/fabricPod.json".format(self.apic_address)
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        pods = response['imdata']
        for pod_dict in pods:
            pod_mo_class = pod_dict.keys()[0]
            pod = pod_dict[pod_mo_class]['attributes']
            if target_node:
                options = '?query-target-filter=eq(fabricNode.id,"{0}")'.format(target_node)
            else:
                options = ''
            uri = "https://{0}/api/class/fabricNode.json".format(self.apic_address)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            nodes = response['imdata']
            for node_dict in nodes:
                node_mo_class = node_dict.keys()[0]
                node = node_dict[node_mo_class]['attributes']
                if node['role'] == 'leaf' and pod['dn'] in node['dn']:
                    node_rn = 'node-' + node['id']
                    leaf_nodes.append(node_rn)

        # Query l1PhysIf to buils self.idict
        uri = "https://{0}/api/class/l1PhysIf.json".format(self.apic_address)
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        intfs = response['imdata']
        if intfs:
            for intf_dict in intfs:
                intf_mo_class = intf_dict.keys()[0]
                intf = intf_dict[intf_mo_class]['attributes']
                node = intf['dn'].split('/')[2]
                pod_id = intf['dn'].split('/')[1].replace('pod-', '')
                if node in leaf_nodes:
                    node_id = node.replace('node-', '')
                    intf_id =  intf['id'].strip('eth')
                    portT = intf['portT']
                    usage = intf['usage']
                    descr = intf['descr']
                    if len(intf_id.split('/')) == 3:
                        fex = intf_id.split('/')[0]
                        module = intf_id.split('/')[1]
                        port = intf_id.split('/')[2]
                    elif len(intf_id.split('/')) == 2:
                        fex = '0'
                        module = intf_id.split('/')[0]
                        port = intf_id.split('/')[1]
                    idx = int(node.split('-')[-1])*1000000 + int(fex)*1000 + int(module)*100 + int(port)
                    self.idict[idx] = {'node': node_id, 'intf_id': intf_id, 'portT': portT, 'usage': usage, 'descr': descr,
                                       'pod': pod_id, 'operSt': '', 'operSpeed': '', 'operDuplex': ''}
            # Query ethpmPhysIf and add status, speed and duplex to self.idict
            uri = "https://{0}/api/class/ethpmPhysIf.json".format(self.apic_address)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            phy_intfs = response['imdata']
            for phy_intf_dict in phy_intfs:
                phy_intf_mo_class = phy_intf_dict.keys()[0]
                phy_intf = phy_intf_dict[phy_intf_mo_class]['attributes']
                node = phy_intf['dn'].split('/')[2]
                if node in leaf_nodes:
                    pod = phy_intf['dn'].split('/')[1].replace('pod-', '')
                    node = phy_intf['dn'].split('/')[2].replace('node-', '')
                    match = re.findall('\[eth.*\]', phy_intf['dn'])
                    if match:
                        intf_id = match[0].strip('[eth]')
                        if len(intf_id.split('/')) == 3:
                            fex = intf_id.split('/')[0]
                            module = intf_id.split('/')[1]
                            port = intf_id.split('/')[2]
                        elif len(intf_id.split('/')) == 2:
                            fex = '0'
                            module = intf_id.split('/')[0]
                            port = intf_id.split('/')[1]
                        search_idx = int(node.split('-')[-1])*1000000 + int(fex)*1000 + int(module)*100 + int(port)
                        if search_idx in self.idict:
                            self.idict[search_idx]['operSt'] = phy_intf['operSt']
                            self.idict[search_idx]['operSpeed'] = phy_intf['operSpeed']
                            self.idict[search_idx]['operDuplex'] = phy_intf['operDuplex']

        # Match idx in self.idict and port_profiles to add port_sr_name and policy_group
        for key in self.idict:
            if key in port_profiles:
                self.idict[key]['port_sr_name'] = port_profiles[key]['port_sr_name']
                self.idict[key]['policy_group'] = port_profiles[key]['policy_group']
            else:
                self.idict[key]['port_sr_name'] = ''
                self.idict[key]['policy_group'] = ''

    def get_vlan_pool(self):

        result = self.refresh_connection()

        if result[0] == 1:
            return

        self.vlan_pools = []
        uri = 'https://{0}/api/class/fvnsVlanInstP.json?rsp-subtree=children'.format(self.apic_address)
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        for inst in response['imdata']:
            name = inst['fvnsVlanInstP']['attributes']['name']
            alloc = inst['fvnsVlanInstP']['attributes']['allocMode']
            domains = []
            if 'children' in inst['fvnsVlanInstP']:
                for child in inst['fvnsVlanInstP']['children']:
                    if 'fvnsRtVlanNs' in child:
                        domains.append(child['fvnsRtVlanNs']['attributes']['tDn'].split('uni/')[1])
                for child in inst['fvnsVlanInstP']['children']:
                    if 'fvnsEncapBlk' in child:
                        from_vlan = int(child['fvnsEncapBlk']['attributes']['from'].replace('vlan-', ''))
                        to_vlan = int(child['fvnsEncapBlk']['attributes']['to'].replace('vlan-', ''))
                        self.vlan_pools.append({'name': name, 'alloc': alloc, 'domains': domains,
                                                'from_vlan': from_vlan, 'to_vlan': to_vlan})
 
    def vlan_usage(self, vlan):
        if self.vlan_pools:
            print 'VLAN:', vlan

            y = PrettyTable(
                ['POOL NAME', 'ALLOCATION', 'FROM', 'TO', 'DOMAINS'])
            y.align = "l"
            y.vertical_char = ' '
            y.junction_char = ' '

            for item in self.vlan_pools:
                if (int(vlan) >= item['from_vlan']) and (int(vlan) <= item['to_vlan']):
                    name = item['name']
                    alloc = item['alloc']
                    from_vlan = item['from_vlan']
                    to_vlan = item['to_vlan']
                    domains = str(item['domains'])[1:-2]
                    y.add_row([name, alloc, from_vlan, to_vlan, domains])
        print(y)

        if self.epgs:
            print '\n'
            y = PrettyTable(
                ['TENANT', 'APP_PROFILE', 'EPG', 'TAGS'])
            y.align = "l"
            y.vertical_char = ' '
            y.junction_char = ' '

            for epg in self.epgs:
                vlan_used = False
                for path in epg['paths']:
                    if str(vlan) == path['encap']:
                        vlan_used = True
                
                if vlan_used:
                    tenant = epg['tn']
                    ap_profile = epg['ap']
                    epg_name = epg['name']
                    tags = epg['tags']

                    y.add_row([tenant, ap_profile, epg_name, tags])
        print(y)
       
    def print_epgs(self):
        for epg in self.epgs:
            print '\n'
            print 'TN:', epg['tn']
            print 'AP:', epg['ap']
            print 'EPG:', epg['name']
            print 'TAG:', epg['tags']
            print 'BD:', epg['bd']

            y = PrettyTable(
                ['NODE', 'INTERFACE', 'VLAN', 'TOPOLOGY', 'USAGE', 'STATE', 'SPEED', 'PORT_SR_NAME',
                                  'POLICY_GROUP'])
            y.align = "l"
            y.vertical_char = ' '
            y.junction_char = ' '

            for path in epg['paths']:
                if 'vpc' in path:
                    for idx in self.idict:
                        if (path['vpc'] == self.idict[idx]['policy_group']) and (self.idict[idx]['node'] in path['protpaths']):
                            node = self.idict[idx]['node']
                            intf_id = self.idict[idx]['intf_id']
                            port_t = self.idict[idx]['portT']
                            usage = self.idict[idx]['usage']
                            oper_st = self.idict[idx]['operSt']
                            oper_speed = self.idict[idx]['operSpeed']
                            port_sr_name = self.idict[idx]['port_sr_name']
                            policy_group = self.idict[idx]['policy_group']
                            vlan = path['encap']
                            y.add_row([node, intf_id, vlan, port_t, usage, oper_st, oper_speed, port_sr_name,
                                       policy_group])

                elif 'pc' in path:
                    for idx in self.idict:
                        if (path['pc'] == self.idict[idx]['policy_group']) and (self.idict['node'] == path['node']):
                            node = self.idict[idx]['node']
                            intf_id = self.idict[idx]['intf_id']
                            port_t = self.idict[idx]['portT']
                            usage = self.idict[idx]['usage']
                            oper_st = self.idict[idx]['operSt']
                            oper_speed = self.idict[idx]['operSpeed']
                            port_sr_name = self.idict[idx]['port_sr_name']
                            policy_group = self.idict[idx]['policy_group']
                            vlan = path['encap']
                            y.add_row([node, intf_id, vlan, port_t, usage, oper_st, oper_speed, port_sr_name,
                                       policy_group])


                elif path['idx'] in self.idict:
                    key = path['idx']
                    node = self.idict[key]['node'].replace('node-', '')
                    intf_id = self.idict[key]['intf_id']
                    port_t = self.idict[key]['portT']
                    usage = self.idict[key]['usage']
                    oper_st = self.idict[key]['operSt']
                    oper_speed = self.idict[key]['operSpeed']
                    port_sr_name = self.idict[key]['port_sr_name']
                    policy_group = self.idict[key]['policy_group']
                    vlan = path['encap']
                    y.add_row([node, intf_id, vlan, port_t, usage, oper_st, oper_speed, port_sr_name,
                               policy_group])

            print(y)

    def print_interface(self):
        print '* - flag indicates configured but not mapped to any EPG interfaces'

        y = PrettyTable(["F", "NODE", "INTERFACE", "TOPOLOGY", "USAGE", "STATE", "SPEED", "PORT_SR_NAME",
                         "POLICY_GROUP"])
        y.align = "l"
        y.vertical_char = ' '
        y.junction_char = ' '

        for key in sorted(self.idict):
            flag = ''
            node = self.idict[key]['node'].replace('node-', '')
            intf_id = self.idict[key]['intf_id']
            port_t = self.idict[key]['portT']
            usage = self.idict[key]['usage']
            oper_st = self.idict[key]['operSt']
            oper_speed = self.idict[key]['operSpeed']
            port_sr_name = self.idict[key]['port_sr_name']
            policy_group = self.idict[key]['policy_group']
            if ('discovery' in usage) and (port_sr_name or policy_group):
                flag = '*'
            y.add_row([flag, node, intf_id, port_t, usage, oper_st, oper_speed, port_sr_name, policy_group])
        print(y)

    def print_interface_details(self, key):
        print '* - flag indicates configured but not mapped to any EPG interfaces'

        y = PrettyTable(["F", "NODE", "INTERFACE", "TOPOLOGY", "USAGE", "STATE", "SPEED", "PORT_SR_NAME",
                         "POLICY_GROUP"])
        y.align = "l"
        y.vertical_char = ' '
        y.junction_char = ' '

        flag = ''
        node = self.idict[key]['node'].replace('node-', '')
        intf_id = self.idict[key]['intf_id']
        port_t = self.idict[key]['portT']
        usage = self.idict[key]['usage']
        oper_st = self.idict[key]['operSt']
        oper_speed = self.idict[key]['operSpeed']
        port_sr_name = self.idict[key]['port_sr_name']
        policy_group = self.idict[key]['policy_group']
        if ('discovery' in usage) and (port_sr_name or policy_group):
            flag = '*'
        y.add_row([flag, node, intf_id, port_t, usage, oper_st, oper_speed, port_sr_name, policy_group])
        print(y)

        print '\n EPG Binding Info: \n'

        y = PrettyTable(["TENANT", "APP PROFILE", "EPG", "BD", "VLAN_ENCAP"])
        y.align = "l"
        y.vertical_char = ' '
        y.junction_char = ' '

        for epg in self.epgs:
            for path in epg['paths']:
                if 'vpc' in path:
                    if (path['vpc'] == self.idict[key]['policy_group']) and (str(key)[:3] in path['protpaths']):
                        vlan = path['encap']
                        y.add_row([epg['tn'], epg['ap'], epg['name'], epg['bd'], vlan])

                elif path['idx'] == key:
                    vlan = path['encap']
                    y.add_row([epg['tn'], epg['ap'], epg['name'], epg['bd'], vlan])
        print (y)

    def print_vlan_pool(self):
        y = PrettyTable(["NAME", "ALLOCATION", "FROM", "TO", "DOMAINS"])
        y.align = "l"

        y.vertical_char = ' '
        y.junction_char = ' '
        for item in self.vlan_pools:
            name = item['name']
            alloc = item['alloc']
            from_vlan = item['from_vlan']
            to_vlan = item['to_vlan']
            domains = str(item['domains'])[1:-1]
            y.add_row([name, alloc, from_vlan, to_vlan, domains])
        print(y)

    def print_snapshot(self):
        self.collect_snapshots()
        y = PrettyTable(["ID", "TRIGGER", "TIME", "DESCRIPTION" ])
        y.align = "l"
        y.vertical_char = ' '
        y.junction_char = ' '


        snapshot_id = 0

        for snapshot in self.snapshots:
            trigger = ''
            dn = snapshot['configSnapshot']['attributes']['dn']
            if 'OneTime' in dn:
                trigger = 'OneTime'
            elif 'DailyAuto' in dn:
                trigger = 'DailyAuto'
            elif 'defaultAuto' in dn:
                trigger = 'defaultAuto'

            snapshot_time = snapshot['configSnapshot']['attributes']['createTime']
            descr = snapshot['configSnapshot']['attributes']['descr']
            y.add_row([snapshot_id, trigger, snapshot_time, descr])
            snapshot_id += 1

        print(y)

 
if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    try:
        apic = Apic()
        apic.prompt = 'ACLI()>'
        apic.cmdloop('Starting ACLI...')
    except KeyboardInterrupt:
        print "\nINFO: ACLI Shell was interrupted by Ctrl-C"
        apic.disconnect()
