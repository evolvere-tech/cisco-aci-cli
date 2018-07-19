#!/usr/bin/env python
import requests
import json
import pprint
from collections import defaultdict
from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning
from evoACISettings import FABRICS


#FABRICS = {'uk-dc1': [
#    {'address': '10.50.137.202', 'username': 'admin', 'password': 'C1sco123'},
#     ],
#           'uk-dc2': [
#    {'address': '10.50.137.92', 'username': 'admin', 'password': 'C1sco123'},
#     ],
#}

class Apic():
    # APIC login, connect and disconnect functions
    def __init__(self):
        self.can_connect = ''
        self.fabric = []
        self.apic_address = None
        self.cookie = None
        self.headers = {'content-type': "application/json", 'cache-control': "no-cache"}
        self.epg_names = []
        self.idict = {}
        self.session = requests.Session()
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
        requests.packages.urllib3.disable_warnings(SNIMissingWarning)

    def login(self, args):
        """Usage: login [FABRIC_NAME]"""
        msg = None
        if self.can_connect:
            try:
                self.disconnect()
            except:
                pass
        self.can_connect = ''
        if len(args) == 0:
            msg = "Usage: login [FABRIC_NAME]"
            return [1, msg]
        else:
            parameter_values = args.split()
            if parameter_values[0] in FABRICS.keys():
                self.fabric = FABRICS[parameter_values[0]]
                username = ''
                password = ''
                for apic_credentials in self.fabric:
                    if not apic_credentials['username'] or not apic_credentials['password']:
                        if not username or not password:
                            msg = 'ERROR: No username or password for fabric {0}'.format(self.fabric)
                    else:
                        username = apic_credentials['username']
                        password = apic_credentials['password']
                    address = apic_credentials['address']
                    try:
                        self.connect(address=address, username=username, password=password)
                        self.can_connect = parameter_values[0]
                        msg = 'Established connection to APIC in fabric', self.can_connect
                        return [0, msg]
                    except Exception as error:
                        msg = 'ERROR:', str(error)
                        return [1, msg]
                if not self.can_connect:
                    msg = 'Cannot connect to APIC in fabric', parameter_values[0]
                    return [1, msg]
        return [1, msg]

    def connect(self, **kwargs):
        if kwargs:
            apic_user = kwargs['username']
            apic_password = kwargs['password']
            apic_address = kwargs['address']
            uri = "https://{0}/api/aaaLogin.json".format(apic_address)
            payload = {'aaaUser': {'attributes': {'name': apic_user, 'pwd': apic_password}}}
            response = self.session.post(uri, data=json.dumps(payload), headers=self.headers, verify=False, timeout=10)
            self.cookie = {'APIC-cookie': response.cookies['APIC-cookie']}
            self.apic_address = apic_address
        else:
            pass

    def disconnect(self):
        try:
            self.session.close()
        except:
            pass

    #
    # ACI Fabric functions
    #

    def aci_set_vlan_pool(self, vlanp_name, vlan_start, vlan_end, delete=False):
        """Configures ACI VLAN Pool(fvnsVlanInstP).

        Args:
            vlanp_name: VLAN Pool name.
            vlan_start: Lowest vlan_id.
            vlan_end: Highest vlan_id.

        Returns:
            List with one element.
            0 - success
            1 - error
        """
        try:
            config_payload = {"fvnsVlanInstP":
                                  {"attributes":
                                       {"allocMode": "static"},
                                   "children": [
                                       {"fvnsEncapBlk":
                                            {"attributes":
                                                 {"from": "vlan-{0}".format(vlan_start),
                                                  "to": "vlan-{0}".format(vlan_end),
                                                  }
                                             }
                                        },
                                   ]
                                   },
                              }

            if delete:
                uri = 'https://{0}/api/mo/uni/infra/vlanns-[{1}]-static.json'.format(self.apic_address, vlanp_name)
                response = self.session.delete(uri, data=json.dumps(config_payload),
                                               headers=self.headers, cookies=self.cookie, verify=False)

            else:
                uri = 'https://{0}/api/mo/uni/infra/vlanns-[{1}]-static.json'.format(self.apic_address, vlanp_name)
                response = self.session.post(uri, data=json.dumps(config_payload),
                                             headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_set_pdom(self, pdom_name, vlanp_name, delete=False):
        """Configures ACI Physical Domain(physDomP).

        Args:
            pdom_name: Physical Domain name.
            vlanp_name: VLAN Pool name.

        Returns:
            List with one element.
            0 - success
            1 - error
        """
        try:
            config_payload = {"physDomP":
                                   {"attributes":
                                       {"name": pdom_name},
                                    "children":[
                                        {"infraRsVlanNs":
                                            {"attributes":{"tDn":"uni/infra/vlanns-[{0}]-static".format(vlanp_name)},
                                             "children":[]}
                                        },
                                          ]
                                   }
                              }

            if delete:
                uri = 'https://{0}/api/mo/uni/phys-{1}.json'.format(self.apic_address, pdom_name)
                response = self.session.delete(uri, data=json.dumps(config_payload),
                                               headers=self.headers, cookies=self.cookie, verify=False)

            else:
                uri = 'https://{0}/api/mo/uni.json'.format(self.apic_address)
                response = self.session.post(uri, data=json.dumps(config_payload),
                                             headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_pdom(self, pdom_name):
        """Check for ACI physical domain (physDomP).

        Args:
            pdom_name: ACI switch physical domain name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False.
            1 - error
        """
        try:
            classQuery='physDomP'
            propFilter = 'eq(physDomP.name, "{0}")'.format(pdom_name)
            uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['physDomP']['attributes']['name']
                if name == pdom_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_aep(self, aep_name, pdom_name, delete=False):
        """Configures ACI Attachable Entity Profile(infraAttEntityP).

        Args:
            aep_name: ACI AEP name.
            pdom_name: Physical Domain name.

        Returns:
            List with one element.
            0 - success
            1 - error
        """
        try:
            config_payload = {"infraInfra":
                                  {"attributes":
                                       {},
                                   "children": [
                                       {"infraAttEntityP":
                                            {"attributes":
                                                 {"name": "AEP_COMPUTE"},
                                             "children": [
                                                 {"infraRsDomP":
                                                      {"attributes":
                                                           {"tDn": "uni/phys-{0}".format(pdom_name)}
                                                       }
                                                  },
                                             ]

                                             }
                                        },
                                   ]
                                   }
                              }
            if delete:
                uri = 'https://{0}/api/mo/uni/infra/attentp-{1}.json'.format(self.apic_address, aep_name)
                response = self.session.delete(uri, data=json.dumps(config_payload),
                                               headers=self.headers, cookies=self.cookie, verify=False)

            else:
                uri = 'https://{0}/api/mo/uni/infra.json'.format(self.apic_address)
                response = self.session.post(uri, data=json.dumps(config_payload),
                                             headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_set_switch_profile(self, switch_profile_name, switch_selector_name, node):
        """Configures ACI switch profile (infraNodeP).

        Args:
            switch_profile_name: ACI switch profile name.
            switch_selector_name: ACI switch selector name.

        Returns:
            List with one element.
            0 - success
            1 - error
        """
        try:
            config_payload = {"infraNodeP":
                                {"attributes":
                                     {"name": switch_profile_name
                                      },
                                 "children":
                                     [
                                         {"infraLeafS":
                                             {"attributes":
                                                  {"type": "range",
                                                   "name": switch_selector_name
                                                   },
                                              "children":
                                                  [
                                                      {"infraNodeBlk":
                                                          {"attributes":
                                                               {"from_": node,
                                                                "to_": node,
                                                                "name": node
                                                                },
                                                           "children": []
                                                           }
                                                       }
                                                  ]
                                              }
                                          }
                                     ]
                                 }
                              }

            uri = 'https://{0}/api/node/mo/uni/infra/nprof-{1}.json'.format(self.apic_address, switch_profile_name)

            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0,]
        except Exception as error:
            return [1, str(error)]

    def aci_get_switch_profile(self, profile_name):
        """Check for ACI switch profile (infraNodeP).

        Args:
            profile_name: ACI switch profile name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False.
            1 - error
        """
        try:
            name = ''
            uri = 'https://{0}/api/node/mo/uni/infra/nprof-{1}.json'.format(self.apic_address, profile_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['infraNodeP']['attributes']['name']
                if name == profile_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_interface_profile(self, profile_name):
        """Configure ACI interface profile (infraAccPortP).

        Args:
            profile_name: ACI interface profile name.

        Returns:
            List with two elements.
            0 - success.
            1 - error
        """
        try:
            config_payload = {"infraAccPortP":
                                  {"attributes":
                                       {"name": profile_name},
                                   "children": []
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/accportprof-{1}.json'.format(self.apic_address, profile_name)
            response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie,
                                         verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0,]
        except Exception as error:
            return [1, str(error)]

    def aci_get_interface_profile(self, profile_name):
        """Check for ACI interface profile (infraAccPortP).

        Args:
            profile_name: ACI interface profile name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False.
            1 - error
        """
        try:
            name = ''
            uri = 'https://{0}/api/node/mo/uni/infra/accportprof-{1}.json'.format(self.apic_address, profile_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['infraAccPortP']['attributes']['name']
                if name == profile_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_switch_interface_profile_association(self, switch_profile, interface_profile):
        """Configure ACI switch profile to ACI interface profile association.

        Args:
            switch_profile: ACI switch profile name.
            interface_profile: ACI interface profile name.

        Returns:
            List with two elements.
            0 - success.
            1 - error
        """
        try:
            config_payload = {"infraRsAccPortP":
                                  {"attributes":
                                       {"tDn": "uni/infra/accportprof-{}".format(interface_profile)}
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/nprof-{1}.json'.format(self.apic_address, switch_profile)
            response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie,
                                         verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0,]
        except Exception as error:
            return [1, str(error)]

    def aci_set_link_level_policy(self, policy_name, speed, neg):
        """Configure ACI link level policy (fabricHIfPol).

        Args:
            policy_name: ACI Link Level policy name.
            speed: ACI interface speed (1G or 100M).
            neg: ACI interface auto-negotiation status (on or off)

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        valid_args = ['1G', '100M']
        if speed not in valid_args:
            return [1, 'Invalid arg: options are 1G or 100M.']
        valid_args = ['on', 'off']
        if neg not in valid_args:
            return [1, 'Invalid arg: options are ON or OFF.']
        try:
            config_payload = {"fabricHIfPol":
                                  {"attributes":
                                       {"name": policy_name,
                                        "speed": speed,
                                        "autoNeg": neg
                                        },
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/hintfpol-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_link_level_policy(self, policy_name):
        """Check for ACI link level policy (fabricHIfPol).

        Args:
            policy_name: ACI Link Level policy name.

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/hintfpol-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['fabricHIfPol']['attributes']['name']
                if name == policy_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_cdp_policy(self, policy_name, cdp):
        """Configure ACI CDP policy (cdpIfPol).

        Args:
            policy_name: ACI CDP policy name.
            cdp: CDP status (enabled or disabled).

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        valid_args = ['enabled', 'disabled']
        if cdp not in valid_args:
            return [1, 'Invalid arg: options are enabled or disabled.']
        try:
            config_payload = {"cdpIfPol":
                                  {"attributes":
                                       {"name": policy_name,
                                        "adminSt": cdp
                                        }
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/cdpIfP-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_cdp_policy(self, policy_name):
        """Check ACI CDP policy (cdpIfPol).

        Args:
            policy_name: ACI CDP policy name.

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/cdpIfP-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['cdpIfPol']['attributes']['name']
                if name == policy_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_mcp_policy(self, policy_name, mcp):
        """Configure ACI MCP policy (mcpIfPol).

        Args:
            policy_name: ACI MCP policy name.
            mcp: MCP status (enabled or disabled).

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            valid_args = ['enabled', 'disabled']
            if mcp not in valid_args:
                return [1, 'Invalid arg: options are enabled or disabled.']
            config_payload = {"mcpIfPol":
                                  {"attributes":
                                       {"name": policy_name,
                                        "adminSt": mcp
                                        },
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/mcpIfP-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_mcp_policy(self, policy_name):
        """Check ACI MCP policy (mcpIfPol).

        Args:
            policy_name: ACI MCP policy name.

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/mcpIfP-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['mcpIfPol']['attributes']['name']
                if name == policy_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_lldp_policy(self, policy_name, lldp):
        """Configure ACI LLDP policy (lldpIfPol).

        Args:
            policy_name: ACI LLDP policy name.
            lldp: LLDP status (enabled or disabled).

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            valid_args = ['enabled', 'disabled']
            if lldp not in valid_args:
                return [1, 'Invalid arg: options are enabled or disabled.']
            config_payload = {"lldpIfPol":
                                  {"attributes":
                                       {"name": policy_name,
                                        "adminRxSt": lldp,
                                        "adminTxSt": lldp,
                                        }
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/lldpIfP-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)
            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_lldp_policy(self, policy_name):
        """Check ACI LLDP policy (lldpIfPol).

        Args:
            policy_name: ACI LLDP policy name.
            lldp: LLDP status (enabled or disabled).

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/lldpIfP-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['lldpIfPol']['attributes']['name']
                if name == policy_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_stp_policy(self, policy_name, stp_filter, stp_guard):
        """Configure ACI STP policy (ifPol).

        Args:
            policy_name: ACI STP policy name.
            stp_filter: BPDU filter status (enabled or disabled).
            stp_guard: BPDU guard status (enabled or disabled).

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            valid_args = ['enabled', 'disabled']
            if stp_filter not in valid_args or stp_guard not in valid_args:
                return [1, 'Invalid arg: options are enable or disable.']
            ctrl = []
            if stp_filter == 'enabled':
                filter_name = 'FILTER-ON'
                ctrl.append('bpdu-filter')
            else:
                filter_name = 'FILTER-OFF'
            if stp_guard == 'enabled':
                guard_name = 'GUARD-ON'
                ctrl.append('bpdu-guard')
            else:
                guard_name = 'GUARD-OFF'
            ctrl_str = ','.join(ctrl)
            config_payload = {"stpIfPol":
                                  {"attributes":
                                       {"name": policy_name,
                                        "ctrl": ctrl_str
                                        }
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/ifPol-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_stp_policy(self, policy_name):
        """Check ACI STP policy (ifPol).

        Args:
            policy_name: ACI STP policy name.
            stp_filter: BPDU filter status (enabled or disabled).
            stp_guard: BPDU guard status (enabled or disabled).

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/ifPol-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['stpIfPol']['attributes']['name']
                if name == policy_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_port_channel_policy(self, policy_name, lacp):
        """Configure ACI LACP policy (lacpLagPol).

        Args:
            policy_name: ACI LACP policy name.
            lacp: LACP mode (static, active or passive).

        Returns:
            List with two elements.
            0 - success
            1 - error

        Notes:
            Mapping between ACI displayed parameter values and object values is confusing.
            GUI mode 'Static Channel - Mode On' is stored as 'mode: off' attribute.
        """
        try:
            valid_args = ['static', 'active', 'passive']
            if lacp not in valid_args:
                return [1, 'Invalid arg: options are static, active or passive.']
            if lacp.lower() == 'static':
                mode = 'off'
            elif lacp.lower() == 'active':
                mode = 'active'
            elif lacp.lower() == 'passive':
                mode = 'passive'
            config_payload = {"lacpLagPol":
                                  {"attributes":
                                       {"childAction": "",
                                        "ctrl": "fast-sel-hot-stdby,graceful-conv,susp-individual",
                                        "descr": "",
                                        "maxLinks": "16",
                                        "minLinks": "1",
                                        "mode": mode,
                                        "name": policy_name,
                                        }
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/lacplagp-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_port_channel_policy(self, policy_name):
        """Check ACI LACP policy (lacpLagPol).

        Args:
            policy_name: ACI LACP policy name.

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/lacplagp-{1}.json'.format(self.apic_address, policy_name)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['lacpLagPol']['attributes']['name']
                if name == policy_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_leaf_access_port_policy_grp(self, policy_grp, aep_name, link_level, cdp, mcp, lldp, stp, delete=False):
        """Configure ACI leaf access port policy group (infraAccPortGrp).

        Args:
            policy_grp: ACI policy group eg: IPG_ACC_1G_ON.
            aep_name: ACI AEP name eg: AEP_COMPUTE.
            link_level: ACI Link Level Policy eg: 1G_ON.
            cdp: ACI CDP Policy eg: CDP-ENABLE.
            mcp: ACI MCP Policy eg: MCP-ON.
            lldp: ACI LLDP Policy eg: LLDP-ENABLE.
            stp: ACI STP Policy eg: FILTER-OFF-GUARD-OFF.


        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            config_payload = {"infraAccPortGrp":
                                  {"attributes": {"name": policy_grp
                                                  },
                                   "children": [
                                       {"infraRsAttEntP":
                                           {"attributes":
                                                {"tDn": "uni/infra/attentp-{}".format(aep_name)}
                                            }
                                        },
                                       {"infraRsHIfPol":
                                            {"attributes":
                                                 {"tnFabricHIfPolName": link_level}
                                             }
                                        },
                                       {"infraRsCdpIfPol":
                                            {"attributes":
                                                 {"tnCdpIfPolName": cdp}
                                             }
                                        },
                                       {"infraRsMcpIfPol":
                                            {"attributes":
                                                 {"tnMcpIfPolName": mcp}
                                             }
                                        },
                                       {"infraRsLldpIfPol":
                                            {"attributes":
                                                 {"tnLldpIfPolName": lldp}
                                             }
                                        },
                                       {"infraRsStpIfPol":
                                            {"attributes":
                                                 {"tnStpIfPolName": stp}
                                             }
                                        }]
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/infra/funcprof/accportgrp-{1}.json'.format(self.apic_address, policy_grp)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_leaf_access_port_policy_grp(self, policy_grp):
        """Check for ACI leaf access port policy group (infraAccPortGrp).

        Args:
            policy_grp: ACI policy group eg: IPG_ACC_100M_OFF.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False.
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/funcprof/accportgrp-{1}.json'.format(self.apic_address, policy_grp)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['infraAccPortGrp']['attributes']['name']
                if name == policy_grp:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_pc_policy_grp(self, policy_grp, aep_name, link_level, cdp, mcp, lldp, stp, lacp, delete=False):
        """Configure ACI PC policy group (infraAccBndlGrp).

        Args:
            policy_grp: ACI policy group eg: IPG_ACC_1G_ON.
            aep_name: ACI AEP name eg: AEP_COMPUTE.
            link_level: ACI Link Level Policy eg: 1G_ON.
            cdp: ACI CDP Policy eg: CDP-ENABLE.
            mcp: ACI MCP Policy eg: MCP-ON.
            lldp: ACI LLDP Policy eg: LLDP-ENABLE.
            stp: ACI STP Policy eg: FILTER-OFF-GUARD-OFF.
            lacp: ACI LACP Policy eg: LACP-ACTIVE.

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            config_payload = {"infraAccBndlGrp":
                                  {"attributes":
                                       {"lagT": "link",
                                        "name": policy_grp},
                                   "children": [
                                       {"infraRsAttEntP":
                                            {"attributes":
                                                 {"tDn": "uni/infra/attentp-{0}".format(aep_name)}
                                             }
                                        },
                                       {"infraRsHIfPol":
                                            {"attributes":
                                                 {"tnFabricHIfPolName": link_level}
                                             }
                                        },
                                       {"infraRsCdpIfPol":
                                            {"attributes":
                                                 {"tnCdpIfPolName": cdp}
                                             }
                                        },
                                       {"infraRsMcpIfPol":
                                            {"attributes":
                                                 {"tnMcpIfPolName": mcp}
                                             }
                                        },
                                       {"infraRsLldpIfPol":
                                            {"attributes":
                                                 {"tnLldpIfPolName": lldp}
                                             }
                                        },
                                       {
                                           "infraRsStpIfPol":
                                               {"attributes":
                                                    {"tnStpIfPolName": stp}
                                                }
                                       },
                                       {"infraRsLacpPol":
                                            {"attributes":
                                                 {"tnLacpLagPolName": lacp}
                                             }
                                        }]
                                   }
                              }
            if delete:
                uri = 'https://{0}/api/mo/uni/infra/funcprof/accbundle-{1}.json'.format(self.apic_address, policy_grp)
                response = self.session.delete(uri, data=json.dumps(config_payload),
                                               headers=self.headers, cookies=self.cookie, verify=False)

            else:
                uri = 'https://{0}/api/mo/uni/infra/funcprof.json'.format(self.apic_address)
                response = self.session.post(uri, data=json.dumps(config_payload),
                                             headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_set_vpc_policy_grp(self, policy_grp, aep_name, link_level, cdp, mcp, lldp, stp, lacp, delete=False):
        """Configure ACI VPC policy group (infraAccBndlGrp).

        Args:
            policy_grp: ACI policy group eg: IPG_ACC_100M_OFF.
            aep_name: ACI AEP name eg: AEP_COMPUTE.
            link_level: ACI Link Level Policy eg: 100M_OFF.
            cdp: ACI CDP Policy eg: CDP-ENABLE.
            mcp: ACI MCP Policy eg: MCP-ON.
            lldp: ACI LLDP Policy eg: LLDP-ENABLE.
            stp: ACI STP Policy eg: FILTER-OFF-GUARD-OFF
            lacp: ACI LACP Policy eg: LACP-ACTIVE

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            config_payload = {"infraAccBndlGrp":
                                 {"attributes":
                                     {"lagT":"node",
                                      "name": policy_grp},
                                  "children":[
                                      {"infraRsAttEntP":
                                          {"attributes":
                                              {"tDn":"uni/infra/attentp-{0}".format(aep_name)}
                                          }
                                      },
                                      {"infraRsHIfPol":
                                           {"attributes":
                                                {"tnFabricHIfPolName": link_level}
                                            }
                                       },
                                      {"infraRsCdpIfPol":
                                           {"attributes":
                                                {"tnCdpIfPolName": cdp}
                                            }
                                       },
                                      {"infraRsMcpIfPol":
                                           {"attributes":
                                                {"tnMcpIfPolName": mcp}
                                            }
                                       },
                                      {"infraRsLldpIfPol":
                                           {"attributes":
                                                {"tnLldpIfPolName": lldp}
                                            }
                                       },
                                      {"infraRsStpIfPol":
                                           {"attributes":
                                                {"tnStpIfPolName": stp}
                                            }
                                       },
                                       {"infraRsLacpPol":
                                            {"attributes":
                                                 {"tnLacpLagPolName": lacp}
                                             }
                                       }]
                                  }
                              }

            if delete:
                uri = 'https://{0}/api/mo/uni/infra/funcprof/accbundle-{1}.json'.format(self.apic_address, policy_grp)
                response = self.session.delete(uri, data=json.dumps(config_payload),
                                               headers=self.headers, cookies=self.cookie, verify=False)

            else:
                uri = 'https://{0}/api/mo/uni/infra/funcprof.json'.format(self.apic_address)
                response = self.session.post(uri, data=json.dumps(config_payload),
                                             headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_vpc_policy_grp(self, policy_grp):
        """Check for ACI VPC policy group (infraAccBndlGrp).

        Args:
            policy_grp: ACI VPC policy group.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False.
            1 - error
        """
        try:
            uri = 'https://{0}/api/node/mo/uni/infra/funcprof/accbundle-{1}.json'.format(self.apic_address, policy_grp)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['infraAccBndlGrp']['attributes']['name']
                if name == policy_grp:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_interface_selector(self, profile_name, selector_name, port, policy_grp, delete=False):
        """Configure ACI interface selector (infraHPortS).

        Args:
            profile_name: ACI interface profile name.
            selector_name: ACI interface selector name.
            port: ACI port number.
            policy_grp: ACI policy group

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message
        """
        try:
            config_payload = {"infraHPortS":
                                  {"attributes":
                                       {"name": selector_name,
                                        "type": "range",
                                       },
                                   "children":[
                                       {"infraPortBlk":
                                           {"attributes":
                                                {
                                                 "name": port,
                                                 "fromPort": port,
                                                 "toPort": port,
                                                }
                                            }
                                       },
                                       {"infraRsAccBaseGrp":
                                           {"attributes":
                                                {
                                                 "tDn":"uni/infra/funcprof/accportgrp-{0}".format(policy_grp),
                                                }
                                            }
                                       },]
                                    }
                             }
            if delete:
                uri = 'https://{0}/api/node/mo/uni/infra/accportprof-{1}/hports-{2}-typ-range.json'.format(self.apic_address,
                                                                                                           profile_name,
                                                                                                           selector_name)

                response = self.session.delete(uri, data=json.dumps(config_payload),
                                               headers=self.headers, cookies=self.cookie,verify=False)

            else:
                uri = 'https://{0}/api/node/mo/uni/infra/accportprof-{1}.json'.format(self.apic_address,
                                                                                      profile_name)

                response = self.session.post(uri, data=json.dumps(config_payload),
                                             headers=self.headers, cookies=self.cookie,verify=False)
            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]


    def aci_set_interface_selector_vpc(self, profile_name, selector_name, port, policy_grp, delete=False):
        """Configure ACI interface selector (infraHPortS).

        Args:
            profile_name: ACI interface profile name.
            selector_name: ACI interface selector name.
            port: ACI port number.
            policy_grp: ACI policy group

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message
        """
        try:
            config_payload = {"infraHPortS":
                                  {"attributes":
                                       {"name": selector_name,
                                        "type": "range",
                                       },
                                   "children":[
                                       {"infraPortBlk":
                                           {"attributes":
                                                {
                                                 "name": port,
                                                 "fromPort": port,
                                                 "toPort": port,
                                                }
                                            }
                                       },
                                       {"infraRsAccBaseGrp":
                                           {"attributes":
                                                {
                                                 "tDn":"uni/infra/funcprof/accbundle-{0}".format(policy_grp),
                                                }
                                            }
                                       },]
                                    }
                             }
            if delete:
                uri = 'https://{0}/api/node/mo/uni/infra/accportprof-{1}/hports-{2}-typ-range.json'.format(self.apic_address,
                                                                                                           profile_name,
                                                                                                           selector_name)

                response = self.session.delete(uri, data=json.dumps(config_payload),
                                               headers=self.headers, cookies=self.cookie,verify=False)

            else:
                uri = 'https://{0}/api/node/mo/uni/infra/accportprof-{1}.json'.format(self.apic_address,
                                                                                      profile_name)

                response = self.session.post(uri, data=json.dumps(config_payload),
                                             headers=self.headers, cookies=self.cookie,verify=False)
            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_interface_selector(self, interface_profile, interface_selector):
        """Check for ACI interface selector (infraHPortS).

        Args:
            profile_name: ACI interface profile name

        Returns:
            List with three elements.
            0 - success, True if found otherwise False, infraPortBlks linked to selector
            1 - error, error message, []
        """
        try:
            classQuery='infraHPortS'
            propFilter1 = 'eq(infraHPortS.name, "{}")'.format(interface_selector)
            propFilter2 = 'wcard(infraHPortS.dn, "accportprof-{}")'.format(interface_profile)
            propFilter = 'and({0}, {1})'.format(propFilter1, propFilter2)
            subtree = 'children'
            subtreeClassFilter = 'infraPortBlk'
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}&rsp-subtree={1}&rsp-subtree-class={2}'.format(propFilter,subtree, subtreeClassFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['infraHPortS']['attributes']['name']
                infraPortBlks = response['imdata'][0]['infraHPortS']['children']
                if name == interface_selector:
                    return [0, True, infraPortBlks]
            return [0, False, []]
        except Exception as error:
            return [1, str(error), []]

    #
    # ACI Tenant Functions.
    #
    def aci_set_vrf(self, vrf_name, tenant_name):
        """Configure ACI VRF (fvCtx).

        Args:
            vrf_name: ACI vrf name.
            bd_name: ACI bridge domain name.

        Returns:
            List with two elements.
            0 - success
            1 - error

        Notes:
            Bridge domain is required when creating a vrf.
        """
        try:
            config_payload = {"fvTenant":
                                  {"attributes":
                                       {"dn": "uni/tn-{}".format(tenant_name)},
                                   "children": [
                                       {"fvCtx":
                                            {"attributes":
                                                 {"name": vrf_name,
                                                  "rn": "ctx-{}".format(vrf_name)
                                                  },
                                             }
                                        }]
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/tn-{1}.json'.format(self.apic_address, tenant_name)
            response = self.session.post(uri, data=json.dumps(config_payload),
                                         headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_vrf(self, vrf_name, tenant_name):
        """Check for ACI VRF (fvCtx).

        Args:
            vrf_name: ACI vrf name.
            tenant_name: ACI tenant name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery='fvCtx'
            propFilter1 = 'eq(fvCtx.name, "{}")'.format(vrf_name)
            propFilter2 = 'wcard(fvCtx.dn, "tn-{}")'.format(tenant_name)
            propFilter = 'and({0}, {1})'.format(propFilter1, propFilter2)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['fvCtx']['attributes']['name']
                if name == vrf_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_l3o(self, l3_out, l3_out_instp, tenant_name):
        """Configure ACI L3OUT (l3extOut).

        Args:
            l3_out: ACI external L3 Out.
            l3_out_instp: ACI external EPG.
            tenant_name: ACI tenant name.

        Returns:
            List with two elements.
            0 - success
            1 - error
        """
        try:
            config_payload = {"l3extOut":
                                  {"attributes":
                                       {"dn": "uni/tn-{0}/out-{1}".format(tenant_name, l3_out),
                                        "name": l3_out,
                                        "rn": "out-{}".format(l3_out)},
                                   "children": [
                                       {"l3extInstP":
                                            {"attributes":
                                                 {"dn": "uni/tn-{0}/out-{1}/instP-{2}".format(tenant_name, l3_out,
                                                                                              l3_out_instp),
                                                  "name": l3_out_instp,
                                                  "rn": "instP-{}".format(l3_out_instp)}
                                             }
                                        }]
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/tn-{1}/out-{2}.json'.format(self.apic_address, tenant_name, l3_out)
            response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers,
                                         cookies=self.cookie,
                                         verify=False)

            if response.status_code != 200:
                return [1, response.status_code]
            return [0, ]
        except Exception as error:
            return [1, str(error)]

    def aci_get_l3o(self, l3_out, tenant_name):
        """Check for ACI VRF (l3extOut).

        Args:
            l3_out: ACI L3OUT name.
            tenant_name: ACI tenant name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery = 'l3extOut'
            propFilter1 = 'eq(l3extOut.name, "{}")'.format(l3_out)
            propFilter2 = 'wcard(l3extOut.dn, "tn-{}")'.format(tenant_name)
            propFilter = 'and({0}, {1})'.format(propFilter1, propFilter2)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['l3extOut']['attributes']['name']
                if name == l3_out:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_bd(self, bd_name, tenant_name, vrf_name, l3_out, arp_flood='yes', delete=False):
        """Configure ACI Bridge Domain (fvBD).

        Args:
            bd_name: ACI bridge domain name.
            tenant_name: ACI tenant name.
            vrf_name: ACI VRF name.
            l3_out: ACI Eternal L3 Out.

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message
        """
        try:
            config_payload = {"fvBD":
                                  {"attributes":
                                       {"name": bd_name,
                                        "arpFlood": arp_flood,
                                        "unkMcastAct": 'flood',
                                        "unkMacUcastAct": 'proxy',
                                        "multiDstPktAct": 'bd-flood',
                                        "ipLearning": 'yes',
                                        "unicastRoute": 'yes',
                                        },
                                   "children": [
                                       {"fvRsBDToOut":
                                           {"attributes":
                                               {
                                                   "tnL3extOutName": l3_out,
                                               }
                                           }
                                       },
                                       {"fvRsCtx":
                                           {"attributes":
                                               {
                                                   "tnFvCtxName": vrf_name,
                                               }
                                           }
                                       },
                                       {"fvRsIgmpsn":
                                           {"attributes":
                                               {
                                                   "tnIgmpSnoopPolName": 'default',
                                               }
                                           }
                                       },
                                       {"fvRsBdToEpRet":
                                           {"attributes":
                                               {
                                                   "tnFvEpRetPolName": 'default',
                                               }
                                           }
                                       },
                                   ]
                                   }
                              }

            if delete:
                uri = 'https://{0}/api/mo/uni/tn-{1}/BD-{2}.json'.format(self.apic_address, tenant_name, bd_name)
                response = self.session.delete(uri, data=json.dumps(config_payload), headers=self.headers,
                                             cookies=self.cookie,verify=False)
            else:
                uri = 'https://{0}/api/mo/uni/tn-{1}.json'.format(self.apic_address, tenant_name)
                response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers,
                                             cookies=self.cookie,verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_bd(self, bd_name, tenant_name):
        """Check for ACI Bridge Domain (fvBD).

        Args:
            bd_name: ACI BD name.
            tenant_name: ACI tenant name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery = 'fvBD'
            propFilter1 = 'eq(fvBD.name, "{}")'.format(bd_name)
            propFilter2 = 'wcard(fvBD.dn, "tn-{}")'.format(tenant_name)
            propFilter = 'and({0}, {1})'.format(propFilter1, propFilter2)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['fvBD']['attributes']['name']
                if name == bd_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_tenant(self, tenant_name):
        """Configure ACI Tenant (fvTenant).

        Args:
            tenant_name: ACI tenant name.

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message
        """

        try:
            config_payload = {"fvTenant":
                                  {"attributes":
                                       {"dn": "uni/tn-{}".format(tenant_name),
                                        "name": tenant_name,
                                        "rn": "tn-{}".format(tenant_name)}
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/tn-{1}.json'.format(self.apic_address, tenant_name)
            response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers,
                                         cookies=self.cookie,verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_tenant(self, tenant_name):
        """Check for ACI Tenant (fvTenant).

        Args:
            tenant_name: ACI tenant name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery = 'fvTenant'
            propFilter = 'eq(fvTenant.name, "{}")'.format(tenant_name)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['fvTenant']['attributes']['name']
                if name == tenant_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_app(self, app_name, tenant_name):
        """Configure ACI Application Profile (fvAp).

        Args:
            tenant_name: ACI tenant name.
            app_name: ACI application profile name.

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message
        """
        try:
            config_payload = {"fvAp":
                                  {"attributes":
                                       {"dn": "uni/tn-{0}/ap-{1}".format(tenant_name, app_name),
                                        "name": "{}".format(app_name),
                                        "rn": "ap-{}".format(app_name)}
                                   }
                              }
            uri = 'https://{0}/api/node/mo/uni/tn-{1}/ap-{2}.json'.format(self.apic_address, tenant_name, app_name)
            response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers,
                                         cookies=self.cookie,verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_app(self, app_name, tenant_name):
        """Check for ACI application profile (fvAp).

        Args:
            app_name: ACI application profile name.
            tenant_name: ACI tenant name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery = 'fvAp'
            propFilter1 = 'eq(fvAp.name, "{}")'.format(app_name)
            propFilter2 = 'wcard(fvAp.dn, "tn-{}")'.format(tenant_name)
            propFilter = 'and({0}, {1})'.format(propFilter1, propFilter2)
            uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['fvAp']['attributes']['name']
                if name == app_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_bd_subnet(self, bd_name, tenant_name, gateway, l3_out, delete=False):
        """Configure ACI Bridge Domain subnet (fvSubnet).

        Args:
            bd_name: ACI bridge domain name.
            tenant_name: ACI tenant name.
            gateway: CIDR (network/prefix) format IP address of default gateway.
            l3_out: ACI Eternal L3 Out.

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message
        """
        try:
            config_payload = {"fvSubnet":
                                  {"attributes":
                                       {"dn": "uni/tn-{0}/BD-{1}/subnet-[{2}]".format(tenant_name, bd_name, gateway),
                                        "ctrl": "unspecified",
                                        "ip": gateway,
                                        "scope": "public,shared",
                                        "rn": "subnet-[{}]".format(gateway)
                                        },
                                   "children": [
                                       {"fvRsBDSubnetToProfile":
                                            {"attributes":
                                                 {"tnL3extOutName": l3_out
                                                  },
                                             }
                                        }]
                                   }
                              }

            if delete:
                pass
            else:
                uri = 'https://{0}/api/node/mo/uni/tn-{1}/BD-{2}/subnet-[{3}].json'.format(self.apic_address, tenant_name, bd_name, gateway)
                response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers,
                                             cookies=self.cookie,verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_bd_subnet(self, bd_name, tenant_name, gateway):
        """Check for ACI Bridge Domain subnet (fvSubnet).

        Args:
            bd_name: ACI bridge domain name.
            tenant_name: ACI tenant name.
            gateway: CIDR (network/prefix) format IP address of default gateway.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery = 'fvSubnet'
            propFilter1 = 'eq(fvSubnet.ip, "{}")'.format(gateway)
            propFilter2 = 'wcard(fvSubnet.dn, "tn-{}")'.format(tenant_name)
            propFilter3 = 'wcard(fvSubnet.dn, "BD-{}")'.format(bd_name)
            propFilter = 'and({0}, {1}, {2})'.format(propFilter1, propFilter2, propFilter3)
            uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['fvSubnet']['attributes']['ip']
                if name == gateway:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def aci_set_epg(self, epg_name, tn_name, ap_name, bd_name, phys_dom, delete=False):
        """Configure for ACI endpoint group (fvAEPg).

        Args:
            epg_name: ACI application profile name.
            tn_name: ACI tenant name.
            ap_name: ACI application profile name.
            bd_name: ACI bridge domain name.
            phys_dom: ACI physical domain.
            contract: ACI contract.

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message
        """
        try:
            config_payload = {"fvAEPg":
                                   {"attributes":
                                        {"descr":"",
                                         "name": epg_name,
                                        },
                                    "children": [
                                        {"fvRsBd":
                                            {"attributes":
                                                {"tnFvBDName":bd_name}

                                             }
                                        },
                                        {"fvRsDomAtt":
                                            {"attributes":
                                                {"rn": 'rsdomAtt-[uni/phys-{0}]'.format(phys_dom)}
                                             }
                                        },
                                        #{"fvRsCons":
                                        #    {"attributes":
                                        #        {"rn": 'rscons-{0}'.format(contract)}
                                        #     }
                                        #},
                                        #{"fvRsProv":
                                        #    {"attributes":
                                        #        {"rn": 'rsprov-{0}'.format(contract)}
                                        #     }
                                        #},
                                          ]
                                   }
                             }
            if delete:
                uri = 'https://{0}/api/mo/uni/tn-{1}/ap-{2}/epg-{3}.json'.format(self.apic_address, tn_name, ap_name, epg_name)
                response = self.session.delete(uri, data=json.dumps(config_payload), headers=self.headers,
                                               cookies=self.cookie, verify=False)

            else:
                uri = 'https://{0}/api/mo/uni/tn-{1}/ap-{2}/epg-{3}.json'.format(self.apic_address, tn_name, ap_name, epg_name)
                response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers,
                                             cookies=self.cookie, verify=False)
            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_epg(self, epg_name, tenant_name, ap_name):
        """Check for ACI endpoint group (fvAEPg).

        Args:
            epg_name: ACI Endpoint Group name.
            tenant_name: ACI tenant name.
            ap_name: ACI application profile name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery = 'fvAEPg'
            propFilter1 = 'eq(fvAEPg.name, "{}")'.format(epg_name)
            propFilter2 = 'wcard(fvAEPg.dn, "tn-{}")'.format(tenant_name)
            propFilter3 = 'wcard(fvAEPg.dn, "ap-{}")'.format(ap_name)
            propFilter = 'and({0}, {1}, {2})'.format(propFilter1, propFilter2, propFilter3)
            uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                name = response['imdata'][0]['fvAEPg']['attributes']['name']
                if name == epg_name:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]

    def switch_node_port_map(self, aci_nodes_str):
        """Return list of ports used mapped to an ACI node.

        Args:
            aci_node: ACI node number.

        Notes:
            Creates data structure to map switch profiles to ACI nodes and ports.
            {'LEAF_101': {'nodes': [101], 'ports': [31, 32]},
             'LEAF_102': {'nodes': [102], 'ports': []},
            }

        Returns:
            {'101': ['31', '32'],
             '102': []
            }

        """
        aci_nodes = []
        for node in aci_nodes_str:
            aci_nodes.append(int(node))
        interface_profiles_ports = {}
        switch_ports = {}

        classQuery = 'infraPortBlk'
        uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
        options = ''
        uri += options
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        for item in response['imdata']:
            port_blk = item['infraPortBlk']['attributes']
            dn = port_blk['dn']
            interface_profile = dn.split('/')[2].split('-')[1]
            port_from = int(port_blk['fromPort'])
            port_to = int(port_blk['toPort']) + 1
            port_range = range(port_from, port_to)
            if interface_profile not in interface_profiles_ports:
                interface_profiles_ports[interface_profile] = port_range
            else:
                interface_profiles_ports[interface_profile] += port_range

        classQuery='infraRtAccPortP'
        uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
        options = ''
        uri += options
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        for item in response['imdata']:
            intprof_switchprof = item['infraRtAccPortP']['attributes']
            dn = intprof_switchprof['dn']
            tdn = intprof_switchprof['tDn']
            interface_profile = dn.split('/')[2].split('-')[1]
            switch_profile = tdn.split('/')[2].split('-')[1]
            if interface_profile in interface_profiles_ports:
                ports = interface_profiles_ports[interface_profile]
            else:
                ports = []
            if switch_profile not in switch_ports:
                switch_ports[switch_profile] = {'ports': ports, 'nodes': []}
            switch_ports[switch_profile]['ports'] += ports

        classQuery='infraNodeBlk'
        uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
        options = ''
        uri += options
        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
        for item in response['imdata']:
            node_blk = item['infraNodeBlk']['attributes']
            dn = node_blk['dn']
            switch_profile = dn.split('/')[2].split('-')[1]
            node_from = int(node_blk['from_'])
            node_to = int(node_blk['to_']) + 1
            node_range = range(node_from, node_to)
            if switch_profile in switch_ports:
                switch_ports[switch_profile]['nodes'] += node_range

        return_dict = {}
        for aci_node in aci_nodes:
            ports = []
            for switch_profile, node_port in switch_ports.items():
                if aci_node in node_port['nodes']:
                    ports += node_port['ports']
            unique_ports = list(set(ports))
            unique_ports_str = []
            for port in unique_ports:
                unique_ports_str.append(str(port))
            aci_node_str = str(aci_node)
            return_dict[aci_node_str] = unique_ports_str
        return [0, return_dict]


    #
    # Legacy Functions
    #

    def aci_get_epg_contracts(self, tn, app, epg):
        try:
            contracts = []

            uri = 'https://{0}/api/mo/uni/tn-{1}/ap-{2}/epg-{3}.json'.format(self.apic_address, tn, app, epg)
            subtree = 'children'
            subtreeClassFilter = 'fvRsCons,fvRsProv'  
            options = '?rsp-subtree={0}&rsp-subtree-class={1}'.format(subtree, subtreeClassFilter)

            uri += options

            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()

            if response['imdata']:
                if response['imdata'][0]['fvAEPg']['children']:
                    for item in response['imdata'][0]['fvAEPg']['children']:
                        key = item.keys()[0]
                        contracts.append({'name': item[key]['attributes']['tnVzBrCPName'], 'pc': key})
            return [0, contracts]
        except Exception as error:
            return [1, str(error)]

    def aci_set_epg_contracts(self, tn, l3out, epg, contracts):

        for contract in contracts:

            config_payload = { contract['pc']:
                                 {"attributes":
                                     {"tnVzBrCPName": contract['name']
                                     }
                                 }
                             }

            uri = 'https://{0}/api/mo/uni/tn-{1}/out-{2}/instP-{3}.json'.format(self.apic_address,tn, l3out, epg)

            response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie,
                                         verify=False)

        return

    def aci_get_l3o_conf(self, tn, l3_out, ext_epg):
        '''Function collecting external subnets from L3O configuration'''
        try:
            l3extOut_ok = False
            l3extInstP_ok = False
            l3extInstPname = ''
            subnets = []
            # Query for l3extOut object and l3extInstP children
            moQuery='tn-{0}/out-{1}'.format(tn, l3_out)
            subtree = 'children'
            subtreeClassFilter = 'l3extInstP'
            uri = "https://{0}/api/node/mo/uni/{1}.json".format(self.apic_address, moQuery)
            options = '?rsp-subtree={0}&rsp-subtree-class={1}'.format(subtree, subtreeClassFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                l3extOut_ok = True
                l3extInstPList = response['imdata'][0]['l3extOut']['children']
                # We only expect 1 item in list
                for l3extInstP in l3extInstPList:
                    l3extInstPname = l3extInstP['l3extInstP']['attributes']['name']
                    if l3extInstPname == ext_epg:
                        # Query for l3extInstP by name
                        classQuery='l3extInstP'
                        propFilter = 'eq(l3extInstP.name, "{0}")'.format(l3extInstPname)
                        subtree = 'children'
                        subtreeClassFilter = 'l3extSubnet'
                        uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
                        options = '?rsp-subtree={0}&rsp-subtree-class={1}&query-target-filter={2}'.format(subtree, subtreeClassFilter, propFilter)
                        uri += options
                        response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
                        if response['imdata']:
                            l3extInstP_ok = True
                            l3extInstP = response['imdata'][0]['l3extInstP']
                            if 'children' in l3extInstP.keys():
                                l3extSubnetList = response['imdata'][0]['l3extInstP']['children']
                                for l3extSubnet in l3extSubnetList:
                                    subnet_ip = l3extSubnet['l3extSubnet']['attributes']['ip']
                                    subnets.append(subnet_ip)
                            return [0, l3extOut_ok, l3extInstP_ok, l3extInstPname, subnets]
            return [1, l3extOut_ok, l3extInstP_ok, l3extInstPname, subnets]
        except Exception as error:
            return [1, str(error)]

    def aci_get_contract(self, name):
        try:
            classQuery='vzBrCP'
            propFilter = 'eq(vzBrCP.name, "{0}")'.format(name)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                return [0, response['imdata']]
            else:
                return [1,]
        except Exception as error:
            return [1, str(error)]

    def aci_get_tenants(self):
        try:
            classQuery='fvTenant'
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                return [0, response['imdata']]
            else:
                return [1,]
        except Exception as error:
            return [1, str(error)]

    def aci_get_epgs(self, tn):
        try:
            classQuery='fvAEPg'
            propFilter = 'wcard(fvAEPg.dn, "tn-{0}")'.format(tn)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                return [0, response['imdata']]
            else:
                return [1,]
        except Exception as error:
            return [1, str(error)]

    def aci_get_l3os(self, tn):
        try:
            classQuery='l3extOut'
            propFilter = 'wcard(l3extOut.dn, "tn-{0}")'.format(tn)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                return [0, response['imdata']]
            else:
                return [1,]
        except Exception as error:
            return [1, str(error)]

    def aci_get_ext_epgs(self, tn, l3o):
        try:
            classQuery='l3extInstP'
            propFilter = 'wcard(l3extInstP.dn, "tn-{0}/out-{1}")'.format(tn, l3o)
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                return [0, response['imdata']]
            else:
                return [1,]
        except Exception as error:
            return [1, str(error)]

    def aci_get_endpoints(self):
        try:
            classQuery='fvCEp'
            uri = "https://{0}/api/class/{1}.json".format(self.apic_address, classQuery)
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                return [0, response['imdata']]
            else:
                return [1,]
        except Exception as error:
            return [1, str(error)]

    def aci_set_static_binding(self, tn_name, ap_name, epg_name, pod, node, port, vlan, trunk=True, delete=False):
        """Configure static binding (fvRsPathAtt).

        Args:
            tn_name: ACI tenant name.
            ap_name: ACI application profile name.
            epg_name: ACI Endpoint Group name.
            pod: ACI pod, usually '1'.
            node: ACI node.
            vlan: VLAN id for data encapsulation.
            trunk: True if .1q trunk.

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message

        """
        if trunk:
            mode = 'regular'
        else:
            mode = 'native'
        try:
            config_payload = {"fvRsPathAtt":
                                   {"attributes":
                                        {"encap": 'vlan-{0}'.format(vlan),
                                         "mode": mode,
                                        }
                                   }
                             }

            uri = 'https://{0}/api/mo/uni/tn-{1}/ap-{2}/epg-{3}/rspathAtt-[topology/pod-{4}/paths-{5}/pathep-[eth1/{6}]].json'.format(self.apic_address, tn_name, ap_name, epg_name, pod, node, port)

            if delete:
                response = self.session.delete(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie, verify=False)

            else:
                 response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']
        except Exception as error:
            return [1, 'REST_ERROR', str(error)]


        return

    def aci_set_static_binding_vpc(self, tn_name, ap_name, epg_name, pod, nodes, policy_grp, vlan, trunk=True, delete=False):
        """Configure VPC static binding (fvRsPathAtt).

        Args:
            tn_name: ACI tenant name.
            ap_name: ACI application profile name.
            epg_name: ACI Endpoint Group name.
            pod: ACI pod, usually '1'.
            nodes: ACI nodes in vPC, separated with '-'. eg '101-102'.
            policy_grp: ACI policy group for vPC.
            vlan: VLAN id for data encapsulation.
            trunk: True if .1q trunk.

        Returns:
            List with three elements.
            0 - success, 200, ''
            1 - error, status code, error message

        """
        if trunk:
            mode = 'regular'
        else:
            mode = 'native'

        try:
            config_payload = {"fvRsPathAtt":
                                   {"attributes":
                                        {"encap": 'vlan-{0}'.format(vlan),
                                         "mode": mode,
                                        }
                                   }
                             }

            uri = 'https://{0}/api/mo/uni/tn-{1}/ap-{2}/epg-{3}/rspathAtt-[topology/pod-{4}/protpaths-{5}/pathep-[{6}]].json'.format(self.apic_address,
                                                                                                                                     tn_name, ap_name, epg_name, pod, nodes, policy_grp)

            if delete:
                response = self.session.delete(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie, verify=False)
            else:
                 response = self.session.post(uri, data=json.dumps(config_payload), headers=self.headers, cookies=self.cookie, verify=False)

            if response.status_code != 200:
                return [1, response.status_code, response.json()['imdata'][0]['error']['attributes']['text']]
            return [0, response.status_code, '']

        except Exception as error:
            return [1, 'REST_ERROR', str(error)]

    def aci_get_static_binding(self, path_name, tenant_name, ap_name, epg_name, vlan):
        """Check for ACI static binding (fvRsPathAtt).

        Args:
            path_name: ACI
            tenant_name: ACI tenant name.
            ap_name: ACI application profile name.
            epg_name: ACI Endpoint Group name.

        Returns:
            List with two elements.
            0 - success, True if found, otherwise False
            1 - error
        """
        try:
            classQuery = 'fvRsPathAtt'
            propFilter1 = 'wcard(fvRsPathAtt.dn, "{}")'.format(path_name)
            propFilter2 = 'wcard(fvRsPathAtt.dn, "tn-{}")'.format(tenant_name)
            propFilter3 = 'wcard(fvRsPathAtt.dn, "ap-{}")'.format(ap_name)
            propFilter4 = 'wcard(fvRsPathAtt.dn, "epg-{}")'.format(epg_name)
            propFilter5 = 'eq(fvRsPathAtt.encap, "vlan-{}")'.format(vlan)
            propFilter = 'and({0}, {1}, {2}, {3}, {4})'.format(propFilter1, propFilter2, propFilter3, propFilter4, propFilter5)
            uri = "https://{0}/api/node/class/{1}.json".format(self.apic_address, classQuery)
            options = '?query-target-filter={0}'.format(propFilter)
            uri += options
            response = self.session.get(uri, headers=self.headers, cookies=self.cookie, verify=False).json()
            if response['imdata']:
                encap = response['imdata'][0]['fvRsPathAtt']['attributes']['encap']
                if encap == 'vlan-' + vlan:
                    return [0, True]
            return [0, False]
        except Exception as error:
            return [1, str(error)]


if __name__ == '__main__':
    apic = Apic()
    apic.login('Sandbox')
    #print apic.aci_get_pdom('PDOM_GLOBAL')
    #print = apic.aci_get_interface_profile('101')
    #print apic.aci_set_interface_selector_vpc('IP_LEAF_101', 'IS_Intf-39', '39', 'IPG_vPC_101_39_102_39')
    print apic.aci_get_interface_selector('IP_LEAF_101', 'IS_Intf-30')
    #print apic.test()
    #print apic.test2()
    #print apic.test3()
    #print apic.switch_node_port_map(['101', '102'])
    #print apic.aci_get_vpc_policy_grp('IPG_vPC_101_40_102_40')
    #print apic.aci_set_vrf('VRF_GLOBAL', 'common')
    #resp = apic.aci_get_vrf('VRF_GEN3', 'common')
    #resp = apic.aci_set_l3o('L3OUT_GEN3', 'EPG_L3OUT_GEN3', 'common')
    #print resp
    #for i in range(1,100):
    #    print apic.aci_set_bd('BD_VL{0:04d}'.format(i), 'common', 'VRF_GLOBAL', 'L3OUT_GEN3', delete=False)
    #    print apic.aci_set_epg('EPG_VL{0:04d}'.format(i), 'MIXED', 'AP_MIXED', 'BD_VL{0:04d}'.format(i), 'PDOM_GLOBAL')
    #print apic.aci_set_static_binding_vpc('MIXED', 'AP_MIXED', 'EPG_10.10.10.0', 'IPG_vPC_101_30_102_30', '1000', trunk=True) 
    #print apic.aci_get_link_level_policy('1G_ON')
    #print apic.aci_get_cdp_policy('CDP-ON')
    #print apic.aci_get_mcp_policy('MCP-ON')
    #print apic.aci_get_lldp_policy('LLDP_ENABLE')
    #print apic.aci_get_stp_policy('FILTER-OFF-GUARD-OFF')
    #print apic.aci_get_port_channel_policy('LACP-ACTIVE')
    #print apic.aci_set_static_binding_vpc('MIXED', 'AP_MIXED', 'EPG_1.1.202.0_24', '1', '101-102', 'IPG_vPC_101_102_01', '202', trunk=True, delete=False)
    #print apic.aci_get_static_binding('IPG_vPC_101_102_02','MIXED','AP_MIXED','EPG_1.1.101.0_24','101')
    apic.disconnect()

