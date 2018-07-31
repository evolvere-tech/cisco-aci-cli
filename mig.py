#!/usr/bin/env python
import sys
import argparse
import string
import pymongo
import datetime
import evoACI
import yaml
import ipaddr
import pprint
from openpyxl import *

with open('baci_metadata.yaml', 'r') as file:
    METADATA = yaml.load(file.read())

def vlan_set_parser(vlan_set):
    error_msg = []
    vlan_list = []
    for vlan in vlan_set.split(','):
        if '-' in vlan:
            for vlan_id in range(int(vlan.split('-')[0]), int(vlan.split('-')[1]) + 1):
                vlan_list.append(str(vlan_id))
        else:
            vlan_list.append(vlan)
    if vlan_list:
        for vlan_id in vlan_list:
            if not (1 < int(vlan_id) < 4096):
                msg = 'ERROR: VLAN {0} is invalid.'.format(vlan_id)
                error_msg.append(msg)
        if error_msg:
            return [1, error_msgs]
        else:
            return [0, vlan_list]
    else:
        return [1, 'ERROR: Empty VLAN list']

def interface_name_normalizer(intf):
    suffix = filter(lambda c: c in string.digits + '/', intf)

    if intf.lower().startswith('e'):
        prefix = 'Ethernet'
    elif intf.lower().startswith('t'):
        prefix = 'TenGigabitEthernet'
    elif intf.lower().startswith('g'):
        prefix = 'GigabitEthernet'
    else:
        return [1, 'ERROR: Unrecognized interface type for ' + intf]

    if prefix:
        interface_name = prefix + suffix
        return [0, interface_name]

    else:
        return [1, 'ERROR: Failed to normalize interface ' + intf]


def link_level_speed_normaliser(speed):
    SPEED_MAP = METADATA['LINK_LEVEL_SPEED_MAP']
    std_speed = ''
    for std_speed_option, interface_speeds in SPEED_MAP.items():
        for interface_speed in interface_speeds:
            if speed == interface_speed:
                std_speed = std_speed_option
    if std_speed:
        return [0, std_speed]
    return [1, ]

def policy_group_speed_normaliser(speed):
    SPEED_MAP = METADATA['POLICY_GROUP_SPEED_MAP']
    std_speed = ''
    for std_speed_option, interface_speeds in SPEED_MAP.items():
        for interface_speed in interface_speeds:
            if speed == interface_speed:
                std_speed = std_speed_option
    if std_speed:
        return [0, std_speed]
    return [1, ]

def autoneg_normaliser(speed, duplex):
    if speed.lower().startswith('10g') or speed.lower().startswith('40g'):
        std_neg = 'auto'
    elif speed.startswith('a-') or duplex.startswith('a-'):
        std_neg = 'auto'
    else:
        std_neg = 'off'
    return [0, std_neg]


def map_link_level_policy(speed, neg):
    link_level_policy_map = METADATA['ACI_LINK_LEVEL_POLICY_MAP']
    link_level_policy = ''
    for policy_option, policy_arg in link_level_policy_map.items():
        if policy_arg['speed'] == speed and policy_arg['autoneg'] == neg:
            link_level_policy = policy_option
    if link_level_policy:
        return [0, link_level_policy]
    return [1, '']


def map_policy_group(speed, neg):
    policy_group_map = METADATA['ACI_POLICY_GROUP_MAP']
    policy_group = ''
    for policy_option, policy_arg in policy_group_map.items():
        if policy_arg['speed'] == speed and policy_arg['autoneg'] == neg:
            policy_group = policy_option
    if policy_group:
        return [0, policy_group]
    return [1, '']


def load_patching_file_xlsx(file_name, vrf, description):
    """Load patching file and create migration.

    Args:
        file_name: path and name of patching schedule file.
        vrf: Target VRF for BDs in a migration
        description: Free text to describe collection of interfaces to be migrated.

    Returns:
        List with two elements.
        0 - success, migration id
        1 - error, [ error messages ]
    """
    msg = []
    error_msg = []
    patching_list = []

    try:
        wb = load_workbook(file_name)
        ws = wb.active
        rows = list(ws.rows)
        fabric_prefix = ''
        for row in rows[1:]:
            if row[0].value and row[1].value and row[2].value and row[3].value:
                device_name = row[2].value.strip().upper()
                interface_temp = row[3].value
                result = interface_name_normalizer(interface_temp)
                if result[0] == 0:
                    interface = result[1]
                else:
                    return [1, result[1]]
                aci_node = row[0].value.split('-')[-1].strip()
                new_fabric_prefix = row[0].value.split('-')[0] + '-' + row[0].value.split('-')[1]
                if fabric_prefix == '':
                    fabric_prefix = new_fabric_prefix

                if new_fabric_prefix != fabric_prefix:
                    error_msg.append('ERROR: Multiple fabrics in the Migration are not supported.')
                    return [1, msg, error_msg]

                aci_intf_temp = filter(lambda c: c in string.digits + '/', row[1].value.strip()).split('/')
                aci_fex_id = 'local'
                if len(aci_intf_temp) == 3:
                    aci_fex_id = aci_intf_temp[0]
                    aci_interface = aci_intf_temp[1] + '/' + aci_intf_temp[2]
                elif len(aci_intf_temp) == 2:
                    aci_interface = aci_intf_temp[0] + '/' + aci_intf_temp[1]
                elif len(aci_intf_temp) == 1:
                    aci_interface = '1' + '/' + aci_intf_temp[-1]
                

                patching_list.append({'device_name': device_name,
                                      'interface': interface,
                                      'aci_node': aci_node,
                                      'aci_interface': aci_interface,
                                      'aci_fex_id': aci_fex_id,
                                     })
        #pprint.pprint(patching_list)
        del(wb)

    except Exception as error:
        error_msg.append(str(error))
        return [1, msg, error_msg]

    fabric = ''
    if fabric_prefix in evoACI.FABRIC_MAP:
        fabric = evoACI.FABRIC_MAP[fabric_prefix]
    else:
        error_msg.append('ERROR: No FABRIC Mapping for Prefix {0}'.format(fabric_prefix))
        return [1, msg, error_msg]

    if patching_list:
        
        result = patching_validate(patching_list)
        if result[0] == 0:
            result = create_migration(patching_list, vrf, description, fabric)
            if result[0] == 0:
                return [0, result[1]]
            else:
                error_msg.append('ERROR: Failed to insert Migration')
                error_msg.append(result[1])
                return [1, msg, error_msg]
        else:
            return [1, msg, result[1]] 
    else:
        error_msg.append('ERROR: Empty import file or file in incorrect format.')
        return [1, msg, error_msg]


def patching_validate(patching):
    """Verify patching information.

    Args:
        patching: List of dictionaries, one dictionary per patch.

                [{'aci_interface': '1/35',
                  'aci_node': '101',
                  'device_name': 'ukdcsw01',
                  'interface': 'Ethernet1/10'}
                ]
    Returns:
        List with two elements.
        0 - success
        1 - error, [ error messages ]
    """
    msgs = []
    switches = []
    aci_nodes = []
    switch_interface_list = []
    node_interface_list = []
    switch_interface_counter = {}
    node_interface_counter ={}
    valid_interfaces_per_vpc = [2,4, 6, 8]
    valid_interfaces_per_lag = [2, 4, 6, 8]
    vpc_intf_counter = {}
    lag_intf_counter = {}
    vpc_interfaces = False

    mongo_client = pymongo.MongoClient()
    db1 = mongo_client.bmap
    interfaces = db1.interface
    inventory = db1.inventory
    db2 = mongo_client.baci
    migrations_data = db2.migrations_data

    # Check for valid aci_node and aci_interface formats
    for item in patching:
        try:
            aci_node = int(item['aci_node'])
            aci_module = int(item['aci_interface'].split('/')[0])
            aci_port = int(item['aci_interface'].split('/')[1])
            if aci_node < 100 or aci_node > 9999 or aci_port > 96:
                msg = 'ERROR: Invalid ACI destination for {0}, {1}'.format(item['device_name'], item['interface'])
                msgs.append(msg)
            else:
                if aci_node not in aci_nodes:
                    aci_nodes.append(aci_node)
        except:
            msg = 'ERROR: Invalid ACI destination for {0}, {1}'.format(item['device_name'], item['interface'])
            msgs.append(msg)
    if msgs:
        return [1, msgs]

    # Create list of unique switch names, list of switch@interface values and list of node@fex_id@interface values.
    for patch in patching:
        if {'device_name': patch['device_name']} not in switches:
            switches.append({'device_name': patch['device_name']})
        switch_interface_list.append('{0}@{1}'.format(patch['device_name'], patch['interface']))
        node_interface_list.append('{0}@{1}@{2}'.format(patch['aci_node'], patch['aci_fex_id'], patch['aci_interface']))

    # Check for duplicate switch_interface values.
    for switch_interface in switch_interface_list:
        # Count number of switch_interface values.
        #
        # switch_interface_counter:
        # {switch_interface: number} eg {'ukdcsw01@Ethernet1/10': 2}
        if switch_interface not in switch_interface_counter:
            switch_interface_counter[switch_interface] = 1
        else:
            switch_interface_counter[switch_interface] += 1

    for switch_interface, count in switch_interface_counter.items():
        if count > 1:
            msgs.append('ERROR: Duplicate switch/interface {0} {1}.'.format(switch_interface.split('@')[0], switch_interface.split('@')[1]))

    # Check for duplicate ACI node_interface values.
    for node_interface in node_interface_list:
        # Count number of node_interface values.
        #
        # node_interface_counter:
        # {node_interface: number} eg {'101@41': 2}
        if node_interface not in node_interface_counter:
            node_interface_counter[node_interface] = 1
        else:
            node_interface_counter[node_interface] += 1

    for node_interface, count in node_interface_counter.items():
        if count > 1:
            msgs.append('ERROR: Duplicate ACI node/interface {0} {1} {2}.'.format(node_interface.split('@')[0],
                                                                                  node_interface.split('@')[1],
                                                                                  node_interface.split('@')[2]))
    if msgs:
        return [1, msgs]

    # Only 1 or 2 switches per migration allowed.
    #if len(switches) > 2:
    #    msgs = ['ERROR: More than 2 switches in patching schedule.',]
    #    return [1, msgs]

    # Number of ACI nodes must match number of switches.
    #if len(aci_nodes) != len(switches):
    #    msgs = ['ERROR: Number of ACI nodes not same as number of legacy switches.',]
    #    return [1, msgs]

    for patch in patching:
        # Check device/interface in discovery db.
        query = interfaces.find_one({'device_name': patch['device_name'], 'interface': patch['interface']})
        if not query:
            msgs.append('ERROR: Interface {0} of Device {1} not in Discovery DB'.format(patch['interface'],
                                                                                       patch['device_name']))
        else:
            # Only HOST interfaces allowed.
            if query['interface_type'] != 'HOST':
                msgs.append('ERROR: Interface {0} of Device {1} not HOST port'.format(patch['interface'],
                                                                                     patch['device_name']))
            else:
                # Check for 10M and 100M half
                std_speed = ''
                std_neg = ''
                # Set std_speed to consistent value as defined in SPEED_MAP meta-data
                result = policy_group_speed_normaliser(query['speed'])
                if result[0] == 0:
                    std_speed = result[1]
                if not std_speed:
                    msg = 'ERROR: Interface speed {0} not mapped to ACI interface speed.'.format(query['speed'])
                    msgs.append(msg)
                # Check valid number of interfaces in VPC
                if 'vpc' in query:
                    patch['vpc'] = query['vpc']
                    # Count number of interfaces in each vpc
                    #
                    # vpc_intf_counter:
                    # {vpc: number} eg {'126': 2}
                    if patch['vpc']:
                        vpc_interfaces = True
                        if patch['vpc'] in vpc_intf_counter:
                            vpc_intf_counter[patch['vpc']] += 1
                        else:
                            vpc_intf_counter[patch['vpc']] = 1
                # Check valid number of interfaces in PC
                if 'lag' in query:
                    patch['lag'] = query['lag']
                    # Count number of interfaces in each lag
                    #
                    # lag_intf_counter:
                    # {lag: number} eg {'126': 2}
                    if patch['lag']:
                        if patch['lag'] in lag_intf_counter:
                            lag_intf_counter[patch['lag']] += 1
                        else:
                            lag_intf_counter[patch['lag']] = 1

    for vpc, intf_count in vpc_intf_counter.items():
        if intf_count not in valid_interfaces_per_vpc:
            msgs.append('ERROR: Invalid number of interfaces in VPC {}'.format(vpc))

    for lag, intf_count in lag_intf_counter.items():
        if intf_count not in valid_interfaces_per_lag:
            msgs.append('ERROR: Invalid number of interfaces in LAG {}'.format(lag))

    for patch in patching:
        # Check that device/interface not in another migration.
        query = migrations_data.find_one({'device_name': patch['device_name'], 'interface': patch['interface']})
        if query:
            msgs.append('ERROR: Interface {0} of Device {1} already in Migration {2}.'.format(patch['interface'],
                                                                                             patch['device_name'],
                                                                                             query['migration_id']))
    # Testing if VPC peers are both present in a migration (only checked if there are VPC interfaces in migration)
    if vpc_interfaces:
        for switch in switches:
            inventory_query = inventory.find_one({'device_name': switch['device_name']})
            if inventory_query:
                if 'vpc_peer' in inventory_query:
                    switch['vpc_peer'] = inventory_query['vpc_peer']
                else:
                    msgs = ['ERROR: Inconsistent VPC data for Device {}'.format(switch['device_name']), ]
                    return [1, msgs]

    if msgs:
        return [1, msgs]
    else:
        return [0, ]


def create_migration(patching, vrf, description, fabric):
    """Create migration database objects.

    Args:
        patching: List of dictionaries, one dictionary per patch.

                [{'aci_interface': '1/35',
                  'aci_node': 'leaf-101',
                  'device_name': 'ukdcsw01',
                  'interface': 'Ethernet1/10',
                  'aci_fex_id': '101'}
                ]

        description: Free text to describe collection of interfaces to be migrated.

    Notes:
        creates two mongo documents:

                > db.migrations.findOne()
                {
                    "_id" : ObjectId("5b2cb272713ffc86f8418e3a"),
                    "migration_id" : "M000001",
                    "status" : "CREATED",
                    "description" : "patching v1",
                    "created" : ISODate("2018-06-22T09:25:22.192Z"),
                    "tasks" : [],
                    "vrf": "VRF_GLOBAL",
                    "fabric": "Sandbox",
                }

                > db.migrations_data.findOne()
                {
                    "_id" : ObjectId("5b2cb272713ffc86f8418e3b"),
                    "status" : "",
                    "migration_id" : "M000001",
                    "migration_date" : "",
                    "device_name" : "ukdcsw01",
                    "aci_node" : "leaf-101",
                    "aci_fex_id": "101",
                    "aci_interface" : "1/35",
                    "interface" : "Ethernet1/10"
                }

    Returns:
        List with two elements.
        0 - success, migration id
        1 - error, error message
    """
    try:
        mongo_client = pymongo.MongoClient()
        db = mongo_client.baci
        migrations = db.migrations
        migrations_data = db.migrations_data

        query = migrations.find({}).sort('migration_id', -1)

        if query.count() > 0:
            last_migration = query.next()['migration_id'].replace('M', '')
            migration_id = 'M{0:06d}'.format(int(last_migration) + 1)

        else:
            migration_id = 'M000001'

        migration_created_date = datetime.datetime.now()

        data = {
                'migration_id': migration_id,
                'status': 'CREATED',
                'created': migration_created_date,
                'description': description,
                'tasks': [],
                'vrf': vrf,
                'fabric': fabric,
               }

        result = migrations.insert_one(data)

        for item in patching:
            data = {
                    'device_name': item['device_name'],
                    'interface': item['interface'],
                    'aci_node': item['aci_node'],
                    'aci_interface': item['aci_interface'],
                    'aci_fex_id': item['aci_fex_id'],
                    'migration_id': migration_id,
                    'status': '',
                    'migration_date': '',
                    }

            result = migrations_data.insert_one(data)

        return [0, migration_id]

    except Exception as error:
        return [1, str(error)]


def list_migrations():
    msg = []
    mongo_client = pymongo.MongoClient()
    db = mongo_client.baci
    migrations = db.migrations
 
    template = '{0:7}  {1:10}  {2:20}  {3:32}  {4:12}  {5:20}'
    print template.format('id', 'Fabric', 'VRF', 'Description', 'Status', 'Created')
    query = migrations.find({}).sort('migration_id', 1)

    if query.count() > 0:
        for item in query:
            migration_id = item['migration_id']
            description = item['description']
            status = item['status']
            fabric = item['fabric']
            vrf = item['vrf']
            created = str(item['created'])
            print template.format(migration_id, fabric, vrf, description, status, created)

    return


def view_migration(migration_id):
    mongo_client = pymongo.MongoClient()
    db = mongo_client.baci
    migrations = db.migrations
    migrations_data = db.migrations_data
 
    query = migrations.find_one({'migration_id': migration_id})

    if query:
        print 'id:', query['migration_id']
        print 'Fabric:', query['fabric']
        print 'Vrf:', query['vrf']
        print 'Description:', query['description']
        print 'Status:',  query['status']
        print 'Created:', query['created'].strftime('%d/%b/%Y %H:%M')
        print 
   
        if query['status'] != 'DELETED': 
            template = '{0:7}  {1:15}  {2:24}  {3:10}  {4:10}  {5:10}  {6:15}'
            query = migrations_data.find({'migration_id': migration_id})

            if query.count() > 0:
                print template.format('id', 'Device', 'Interface', 'ACI_Node', 'ACI_FEX_ID', 'ACI_Interface', 'Status')
                for item in query:
                    device_name = item['device_name']
                    interface = item['interface']
                    aci_node = item['aci_node']
                    aci_fex_id = item['aci_fex_id']
                    aci_interface = item['aci_interface']
                    status = item['status']
                    print template.format(migration_id,
                                          device_name,
                                          interface,
                                          aci_node,
                                          aci_fex_id,
                                          aci_interface,
                                          status)
            else:
                print 'ERROR: Migration {0} not found.'.format(migration_id)

    return

def set_migration_status(migration_id, status=None):
    mongo_client = pymongo.MongoClient()
    db = mongo_client.baci
    migrations = db.migrations
    migrations_data = db.migrations_data
    query = migrations.find_one({'migration_id': migration_id})
    if query:
        if status == 'delete':
            if query['status'] != 'DELETED' and query['status'] == 'CREATED':
                migrations.update_one({'_id': query['_id']}, {'$set': {'status': 'DELETED'}})
                migrations_data.delete_many({'migration_id': migration_id})
            else:
                print 'ERROR: Cannot delete Migration {0}.'.format(migration_id)
        elif status == 'configured':
            migrations.update_one({'_id': query['_id']}, {'$set': {'status': 'CONFIGURED'}})
    else:
        print 'ERROR: Migration {0} not found.'.format(migration_id)
    return


def get_migration_status(migration_id):
    mongo_client = pymongo.MongoClient()
    db = mongo_client.baci
    migrations = db.migrations
    migrations_data = db.migrations_data
    query = migrations.find_one({'migration_id': migration_id})
    if query:
        return [0, query['status']]
    return [1, ]

def save_config_args(migration_id, aci_config_args):
    mongo_client = pymongo.MongoClient()
    db = mongo_client.baci
    migrations = db.migrations
    query = migrations.find_one({'migration_id': migration_id})
    if query:
        response = migrations.update_one({'_id': query['_id']}, {'$set': {'config': aci_config_args}})
    else:
        print 'ERROR: Migration {0} not found.'.format(migration_id)
    return

def delete_config_args(migration_id):
    mongo_client = pymongo.MongoClient()
    db = mongo_client.baci
    migrations = db.migrations
    query = migrations.find_one({'migration_id': migration_id})
    if query:
        response = migrations.update_one({'_id': query['_id']}, {'$unset': {'config': {}}})
    else:
        print 'ERROR: Migration {0} not found.'.format(migration_id)
    return


def get_config_args(migration_id):
    mongo_client = pymongo.MongoClient()
    db = mongo_client.baci
    migrations = db.migrations
    query = migrations.find_one({'migration_id': migration_id})
    if query:
        if 'config' in query:
            config_args = query['config']
            return [0, config_args]
    return [1,]


def aci_precheck(migration_id):
    """
    Args:
        migration_id: Migration identifier

    Notes:

        > db.migrations_data.findOne()
        {
            "_id" : ObjectId("5b334a07713ffc292c0e1b6d"),
            "status" : "",
            "migration_id" : "M000001",
            "migration_date" : "",
            "device_name" : "ukdcsw01",
            "aci_node" : "101",
            "aci_fex_id": "101",
            "aci_interface" : "1/35",
            "interface" : "Ethernet1/10"
        }

        mig_data:
        [
           {'_id': ObjectId('5b438beeda80b11be5b58297'),
            'aci_interface': u'1/40',
            'aci_node': u'102',
            'device_name': u'ukdcsw02',
            'interface': u'Ethernet1/12',
            'lag': u'112',
            'migration_date': u'',
            'migration_id': u'M000001',
            'status': u'',
            'vpc': u'112'},
        ]

        vpc_peers:
        List of VPC switch peers.
        [
          ['GBGLO-DC0-FAUSA-5', 'GBGLO-DC0-FAUSA-6']
        ]

        switch_ports:
        Ports in use (configured) for each node.

        vpc_map:
        {vpc: idx} maps vpc number to new idx for policy group name. ie {'112': '01'}


        [{u'aci_fex_id': u'101',
  'aci_interface': '1/8',
  'aci_node': '222',
  'device_name': 'GBGLO-DC0-FAUSA-5',
  'interface': 'Ethernet8',
  'lag': '101',
  'migration_date': '',
  'migration_id': 'M000001',
  'status': '',
  'vpc': '101'},

  'vpc': '101'},
 {'aci_fex_id': '101',
  'aci_interface': '1/2',
  'aci_node': '223',
  'device_name': 'GBGLO-DC0-FAUSA-6',
  'interface': 'Ethernet2',
  'lag': u'101',
  'migration_date': '',
  'migration_id': 'M000001',
  'status': '',
  'vpc': u'101'},


    Returns:
        List with four elements.
        0 - success, messages, error messages, aci_config_args
        1 - error, messages, error messages, aci_config_args

        aci_config_args:
        {'tenant': 'MIXED',
         'ap': 'AP_MIXED',
         'vrf': u'VRF_GLOBAL',
         'fabric': 'Sandbox',
         'l3o': 'L3OUT_FEN',
         'lldp_policy': 'lldp_enabled',
         'mcp_policy': 'mcp_enabled',
         'pdom': 'PDOM_GLOBAL',
         'stp_policy': 'default',
         'epg_bridge': [{'bd': 'BD_1.1.102.0_24', 'epg': 'EPG_1.1.102.0_24'},
                        {'bd': 'BD_L2_VL0300_01', 'epg': 'EPG_L2_VL0300_01'},
                        {'bd': 'BD_1.1.101.0_24', 'epg': 'EPG_1.1.101.0_24'}],
         'interface': [{'bindings': {u'101': {'bd': 'BD_1.1.101.0_24',
                                              'epg': 'EPG_1.1.101.0_24',
                                              'vlan_name': 'Server VLAN'},
                                     u'102': {'bd': 'BD_1.1.102.0_24',
                                              'epg': 'EPG_1.1.102.0_24'
                                              'vlan_name': 'Server VLAN #2'}},
                        'channel': 'single',
                        'is_trunk': True,
                        'link_level_policy': '1G_ON',
                        'node': u'101',
                        'policy_group': 'IPG_ACC_1G_ON',
                        'port': u'1/35'},
                       {'bindings': {u'101': {'bd': 'BD_1.1.101.0_24',
                                              'epg': 'EPG_1.1.101.0_24'},
                                     u'102': {'bd': 'BD_1.1.102.0_24',
                                              'epg': 'EPG_1.1.102.0_24'}},
                        'channel': 'vpc',
                        'is_trunk': True,
                        'link_level_policy': '1G_ON',
                        'node': u'101',
                        'aci_fex_id': '101',
                        'policy_group': u'IPG_vPC_101_102_02',
                        'interface_description': 'sgppsr000000626',
                        'port': u'1/40'}]}
    """
    msgs = []
    warning_msgs = []
    error_msgs = []
    vlans_in_migration = []
    bindings_in_migration = []
    aci_config_args = {}
    aci_config_args['interface'] = []
    vpc_map = {}
    pc_map = {}
    vpc_limit = 20
    pc_limit = 20
    template = '{0:7} {1:15} {2:15} {3:5} {4:5} {5:5} {6:24} {7:8}'
    mongo_client = pymongo.MongoClient()
    db1 = mongo_client.bmap
    interfaces = db1.interface
    inventory = db1.inventory
    db2 = mongo_client.baci
    migrations = db2.migrations
    migrations_data = db2.migrations_data

    query = migrations.find_one({'migration_id': migration_id})

    if query:
        fabric = query['fabric']
        aci_config_args['fabric'] = fabric
        vrf = query['vrf']
        aci_config_args['vrf'] = vrf
        data_query = migrations_data.find({'migration_id': migration_id})
        # Store as list as we need to add fields to this data.
        mig_data = list(data_query)

        if len(mig_data) > 0:
            apic = evoACI.Apic()
            apic.login(fabric)
            if not apic.can_connect:
                sys.exit('ERROR: Failed to connect to any APIC in Fabric {0}'.format(fabric))

            # Add vpc and lag data to mig_data and build list of aci_node
            print 'INFO: Validating VPC, MLAG and PC data.'
            aci_nodes = []
            switches = []
            for patch in mig_data:
                device_name = patch['device_name']
                interface = patch['interface']
                aci_node = patch['aci_node']
                aci_fex_id = patch['aci_fex_id']
                if patch['device_name'] not in switches:
                    switches.append(patch['device_name'])
                if aci_node not in aci_nodes:
                    aci_nodes.append(aci_node)
                intf_query = interfaces.find_one({'device_name': device_name, 'interface': interface})
                if intf_query:
                    patch['vpc'] = intf_query['vpc']
                    patch['lag'] = intf_query['lag']
            # Map ports and nodes to switch_profiles
            switch_ports = []
            result = apic.switch_node_port_map()
            if result[0] == 0:
                switch_ports = result[1]

            # Check we have all vpc peers. Create list of vpc peers.
            vpc_peers = []
            for switch in switches:
                inventory_query = inventory.find_one({'device_name': switch})
                if inventory_query:
                    if 'vpc_peer' in inventory_query:
                        switch_list = [switch, inventory_query['vpc_peer']]
                        switch_list.sort()
                        if switch_list not in vpc_peers:
                            vpc_peers.append(switch_list)
                    else:
                        msgs = ['ERROR: Device {} missing VPC peer.'.format(switch['device_name']), ]
                        return [1, msgs]

            # Check global ACI objects
            print 'INFO: Validating Global Fabric and Tenant objects.'
            ACI_OBJECTS = METADATA['ACI_OBJECTS']
            VPC_POLICY = METADATA['VPC_POLICY']
            # Store AEP
            aci_config_args['aep'] = ACI_OBJECTS['AEP']
            # Check physDomP
            pdom = ACI_OBJECTS['PDOM']
            aci_config_args['pdom'] = pdom
            bd_tenant = ACI_OBJECTS['BD_TENANT']
            aci_config_args['bd_tenant'] = bd_tenant
            vrf_tenant = ACI_OBJECTS['VRF_TENANT']
            aci_config_args['vrf_tenant'] = vrf_tenant

            pdom_exists = apic.aci_get_pdom(pdom)
            if pdom_exists[0] == 0:
                if pdom_exists[1] == False:
                    msg = 'ERROR: Physical Domain {0} not present on ACI fabric.'.format(pdom)
                    error_msgs.append(msg)
            # Check Switch Profiles
            switch_profile_template = ACI_OBJECTS['SWITCH_PROFILE']
            for aci_node in aci_nodes:
                switch_profile_name = switch_profile_template.format(aci_node)
                result = apic.aci_get_switch_profile(switch_profile_name)
                if result[0] == 0:
                    if not result[1]:
                        msg = 'WARNING: Switch profile {} not present on ACI fabric.'.format(switch_profile_name)
                        warning_msgs.append(msg)
                else:
                    msg = 'ERROR: ACI query failed.'
                    error_msgs.append(msg)
            # Check VRF in common tenant
            vrf_exists = apic.aci_get_vrf(vrf, vrf_tenant)
            if vrf_exists[0] == 0:
                if vrf_exists[1] == False:
                    msg = 'ERROR: VRF {0} not present on ACI fabric.'.format(vrf)
                    error_msgs.append(msg)
            # Check L3O in common tenant
            l3_out = ACI_OBJECTS['L3_OUT']
            aci_config_args['l3_out'] = l3_out
            l3o_exists = apic.aci_get_l3o(l3_out, 'common')
            if l3o_exists[0] == 0:
                if not l3o_exists[1]:
                    msg = 'ERROR: L3OUT {0} not present on ACI fabric.'.format(l3_out)
                    error_msgs.append(msg)
            # Check CDP policy
            cdp_policy = VPC_POLICY['CDP_POLICY']
            aci_config_args['cdp_policy'] = cdp_policy
            cdp_policy_exists = apic.aci_get_cdp_policy(cdp_policy)
            if cdp_policy_exists[0] == 0:
                if not cdp_policy_exists[1]:
                    msg = 'ERROR: CDP policy {0} not present on ACI fabric.'.format(cdp_policy)
                    error_msgs.append(msg)
            # Check MCP policy
            mcp_policy = VPC_POLICY['MCP_POLICY']
            aci_config_args['mcp_policy'] = mcp_policy
            mcp_policy_exists = apic.aci_get_mcp_policy(mcp_policy)
            if mcp_policy_exists[0] == 0:
                if not mcp_policy_exists[1]:
                    msg = 'ERROR: MCP policy {0} not present on ACI fabric.'.format(mcp_policy)
                    error_msgs.append(msg)
            # Check LLDP policy
            lldp_policy = VPC_POLICY['LLDP_POLICY']
            aci_config_args['lldp_policy'] = lldp_policy
            lldp_policy_exists = apic.aci_get_lldp_policy(lldp_policy)
            if lldp_policy_exists[0] == 0:
                if not lldp_policy_exists[1]:
                    msg = 'ERROR: LLDP policy {0} not present on ACI fabric.'.format(lldp_policy)
                    error_msgs.append(msg)
            # Check STP policy
            stp_policy = VPC_POLICY['STP_POLICY']
            aci_config_args['stp_policy'] = stp_policy
            stp_policy_exists = apic.aci_get_stp_policy(stp_policy)
            if stp_policy_exists[0] == 0:
                if not stp_policy_exists[1]:
                    msg = 'ERROR: STP policy {0} not present on ACI fabric.'.format(stp_policy)
                    error_msgs.append(msg)
            # Check LACP policy
            lacp_policy = VPC_POLICY['LACP_POLICY']
            aci_config_args['lacp_policy'] = lacp_policy
            lacp_policy_exists = apic.aci_get_port_channel_policy(lacp_policy)
            if lacp_policy_exists[0] == 0:
                if not lacp_policy_exists[1]:
                    msg = 'ERROR: LACP policy {0} not present on ACI fabric.'.format(lacp_policy)
                    error_msgs.append(msg)
            # Check ACI tenant.
            tenant = ACI_OBJECTS['TENANT']
            aci_config_args['tenant'] = tenant
            tenant_exists = apic.aci_get_tenant(tenant)
            if tenant_exists[0] == 0:
                if not tenant_exists[1]:
                    msg = 'ERROR: Tenant {} not present on ACI fabric.'.format(tenant)
                    error_msgs.append(msg)

            # Check ACI application profile.
            ap = ACI_OBJECTS['AP']
            aci_config_args['ap'] = ap
            ap_exists = apic.aci_get_app(ap, tenant)
            if ap_exists[0] == 0:
                if not ap_exists[1]:
                    msg = 'ERROR: Application profile {} not present on ACI fabric.'.format(ap)
                    error_msgs.append(msg)

            # Check each interface
            print 'INFO: Validating fabric interfaces.'
            msg = template.format('id', 'device name', 'interface', 'node', 'fex', 'port', 'policy group', 'LLP')
            msgs.append(msg)
            total = len(mig_data)
            count = 0
            for patch in mig_data:
                device_name = patch['device_name']
                interface = patch['interface']
                aci_node = patch['aci_node']
                aci_fex_id = patch['aci_fex_id']
                aci_interface = patch['aci_interface']
                aci_port = patch['aci_interface'].split('/')[1]
                count += 1
                msg = 'INFO: Processing interface {0:03d} out of {1:03d}.'.format(count, total)
                sys.stdout.write(msg)
                sys.stdout.flush()
                for back in range(0, len(msg)):
                    sys.stdout.write('\b')
                #
                if aci_fex_id == 'local':
                    interface_profile = ACI_OBJECTS['INTERFACE_PROFILE'].format(aci_node)
                    object_exists = apic.aci_get_interface_profile(interface_profile)
                else:
                    interface_profile = ACI_OBJECTS['INTERFACE_PROFILE_FEX'].format(aci_node, aci_fex_id)
                    object_exists = apic.aci_get_interface_profile_fex(interface_profile)
                if object_exists[0] == 0:
                    if not object_exists[1]:
                        msg = 'WARNING: Interface profile {} not present on ACI fabric.'.format(interface_profile)
                        if msg not in warning_msgs:
                            warning_msgs.append(msg)

                interface_selector = ACI_OBJECTS['INTERFACE_SELECTOR_PREFIX'].format(aci_port)
                link_level_policy = ''
                policy_group = ''
                link_level_speed = ''
                policy_group_speed = ''
                std_neg = ''
                vlans_per_interface = []
                bindings = {}
                vpc_nodes = ''
                vpc_fexes = ''
                intf_query = interfaces.find_one({'device_name': device_name, 'interface': interface})
                if intf_query:
                    interface_description = intf_query['description']
                    speed = intf_query['speed']
                    duplex = intf_query['duplex']
                    vpc = intf_query['vpc']
                    lag = intf_query['lag']
                    if intf_query['trunk_vlans']:
                        vlans_parsing_result = vlan_set_parser(intf_query['trunk_vlans'])
                        trunk = True
                    else:
                        vlans_parsing_result = vlan_set_parser(intf_query['vlan'])
                        trunk = False
                    if vlans_parsing_result:
                        if vlans_parsing_result[0] == 0:
                            vlans_in_migration.extend(vlans_parsing_result[1])
                            vlans_per_interface = vlans_parsing_result[1]
                        else:
                            error_msgs.include(vlans_parsing_result[1])
                    # Calculate EPG and BD names and look-up gateway
                    # Generate bindings per interface, and all unique bindings in migration
                    for vlan in vlans_per_interface:
                        vlan_name = ''
                        vlan_query = db1.vlan.find_one({'switches': device_name, 'vlan_id': vlan})
                        if vlan_query:
                            vlan_name = vlan_query['vlan_name']
                            if vlan_query['subnet_ip']:
                                subnet_ip = vlan_query['subnet_ip']
                                ip_obj = ipaddr.IPv4Network(subnet_ip)
                                ip_network = str(ip_obj.network) + '_' + str(ip_obj.prefixlen)
                                suffix = ip_network
                                gateway = vlan_query['gateways']['vip'] + '/' + str(ip_obj.prefixlen)
                                vmac_in_db = vlan_query['gateways']['vmac']
                                if vmac_in_db:
                                    vmac_str = vmac_in_db.replace('.', '')
                                    vmac = ':'.join([vmac_str[i] + vmac_str[i + 1] for i in range(0, 12, 2)]).upper()
                                else:
                                    msg = 'ERROR: Virtual MAC is missing for VLAN {0} in discovery database.'.format(vlan)
                                    error_msgs.append(msg)
                         
                            else:
                                suffix = 'L2_VL{0:04d}_{1:02d}'.format(int(vlan), int(vlan_query['vlan_dup_idx']))
                                gateway = ''
                                vmac = ''
                            bridge_domain_name = 'BD_{0}'.format(suffix)
                            epg_name = 'EPG_{0}'.format(suffix)
                            bindings[vlan] = {'bd': bridge_domain_name, 
                                              'epg': epg_name, 
                                              'gateway': gateway,
                                              'vmac': vmac,
                                              'vlan_name': vlan_name}

                            if bindings[vlan] not in bindings_in_migration:
                                bindings_in_migration.append(bindings[vlan])

                    # Check speed and link level policy
                    # Set std_speed to consistent value as defined in SPEED_MAP meta-data
                    policy_group_neg = ''
                    result = policy_group_speed_normaliser(speed)
                    if result[0] == 0:
                        policy_group_speed = result[1]
                    result = link_level_speed_normaliser(speed)
                    if result[0] == 0:
                        link_level_speed = result[1]
                        result = autoneg_normaliser(speed, duplex)
                        if result[0] == 0:
                            std_neg = result[1]
                        if std_neg == 'auto':
                            policy_group_neg = 'ON'
                        else:
                            policy_group_neg = 'OFF'
                    if not link_level_speed or not std_neg:
                        msg = 'ERROR: Speed/duplex not supported for {0}, {1}.'.format(device_name, interface)
                        error_msgs.append(msg)
                    else:
                        # Set link level policy based on ACI_OBJECTS meta-data.
                        link_level_policy = ACI_OBJECTS['LINK_LEVEL_POLICY'].format(link_level_speed, std_neg)
                        link_level_policy_exists = apic.aci_get_link_level_policy(link_level_policy)
                        if link_level_policy_exists[0] == 0:
                            if link_level_policy[1] == False:
                                msg = 'ERROR: ACI Link Level Policy {} not present on ACI fabric.'.format(link_level_policy)
                                error_msgs.append(msg)
                        else:
                            msg = 'ERROR: ACI query failed.'
                            error_msgs.append(msg)
                            return [1, error_msgs]

                    # Check for Port Channels (LAGs)
                    if not vpc and lag:
                        channel_type = 'lag'
                        # Build list of port channels to build policy group name
                        pc_intfs = []
                        for intf in mig_data:
                            if intf['lag'] == lag and intf['device_name'] == device_name:
                                pc_intfs.append(intf)
                        # Set policy_group to prefix_node_idx ie prefix_101_01
                        policy_group_prefix = ACI_OBJECTS['PC_POLICY_GROUP_PREFIX'] + '_'
                        policy_group_prefix += aci_node
                        if lag in pc_map:
                            policy_group_suffix = '_' + pc_map[lag]
                            policy_group = policy_group_prefix + policy_group_suffix
                        else:
                            pc_idx = 1
                            while pc_idx <= pc_limit:
                                pc_idx_str = '{0:02d}'.format(pc_idx)
                                policy_group = policy_group_prefix + '_' + pc_idx_str

                                # Check if policy already in use on ACI fabric, use vpc get method for pc
                                pc_policy_exists = apic.aci_get_vpc_policy_grp(policy_group)
                                if pc_policy_exists[0] == 0:
                                    if pc_policy_exists[1]:
                                        pc_idx += 1
                                    else:
                                        pc_map[lag] = pc_idx_str
                                        policy_group_suffix = '_' + pc_map[lag]
                                        policy_group = policy_group_prefix + policy_group_suffix
                                        break
                                else:
                                    msg = 'ERROR: ACI query failed.'
                                    error_msgs.append(msg)
                            if pc_idx > pc_limit:
                                policy_group_node = policy_group_prefix.split('_')[2:][0]
                                policy_group = 'ERROR'
                                msg = 'ERROR: Maximum PCs ({0}) on ACI Fabric exceeded for node {1}.'.format(pc_limit, policy_group_node)
                                error_msgs.append(msg)

                    # Check for Virtual Port Channels (MLAGs)
                    elif vpc:
                        vpc_peer_switches = []
                        for switch_list in vpc_peers:
                            if device_name in switch_list:
                                vpc_peer_switches = switch_list
                        channel_type = 'vpc'
                        # Build list of vpcs to build policy group name
                        vpc_intfs = []
                        for intf in mig_data:
                            if intf['vpc'] == vpc and intf['device_name'] in vpc_peer_switches:
                                vpc_intfs.append(intf)
                        vpc_intfs_sorted = sorted(vpc_intfs, key=lambda i: i['aci_node'])
                        # Set policy_group to prefix_node_node_idx ie prefix_101_102_01
                        policy_group_prefix = ''
                        for intf in vpc_intfs_sorted:
                            if intf['aci_node'] not in policy_group_prefix:
                                # Number of fexes must match number of nodes, so only add fex_id when node is added.
                                if vpc_fexes:
                                    vpc_fexes += '-'
                                vpc_fexes += intf['aci_fex_id']
                                if policy_group_prefix:
                                    vpc_nodes += '-'
                                    policy_group_prefix += '_'
                                else:
                                    policy_group_prefix = ACI_OBJECTS['VPC_POLICY_GROUP_PREFIX'] + '_'
                                vpc_nodes += intf['aci_node']
                                policy_group_prefix += intf['aci_node']
                        if vpc in vpc_map:
                            policy_group_suffix = '_' + vpc_map[vpc]
                            policy_group = policy_group_prefix + policy_group_suffix
                        else:
                            vpc_idx = 1
                            while vpc_idx <= vpc_limit:
                                vpc_idx_str = '{0:02d}'.format(vpc_idx)
                                policy_group = policy_group_prefix + '_' + vpc_idx_str
                                vpc_policy_exists = apic.aci_get_vpc_policy_grp(policy_group)
                                if vpc_policy_exists[0] == 0:
                                    if vpc_policy_exists[1]:
                                        vpc_idx += 1
                                    else:
                                        vpc_map[vpc] = vpc_idx_str
                                        policy_group_suffix = '_' + vpc_map[vpc]
                                        policy_group = policy_group_prefix + policy_group_suffix
                                        break
                                else:
                                    msg = 'ERROR: ACI query failed.'
                                    error_msgs.append(msg)
                            if vpc_idx > vpc_limit:
                                policy_group_nodes = ' '.join(policy_group_prefix.split('_')[2:])
                                policy_group = 'ERROR'
                                msg = 'ERROR: Maximum VPCs ({0}) on ACI Fabric exceeded for nodes {1}.'.format(vpc_limit, policy_group_nodes)
                                error_msgs.append(msg)
                        # VPC FEX restrictions
                        if vpc_fexes:
                            fex_list = vpc_fexes.split('-')
                            fex_set = set(fex_list)
                            if len(fex_set) > 1:
                                msg = 'ERROR: FEX ids not matching for links in VPC {}.'.format(policy_group)
                                if msg not in error_msgs:
                                    error_msgs.append(msg)
                        # Check if policy already in use on ACI fabric
                        vpc_policy_exists = apic.aci_get_vpc_policy_grp(policy_group)
                        if vpc_policy_exists[0] == 0:
                            if vpc_policy_exists[1]:
                                msg = 'ERROR: Policy group {0} is present on ACI Fabric.'.format(policy_group)
                                error_msgs.append(msg)

                    # Single attached ports use pre-configured leaf policy group
                    else:
                        channel_type = 'single'
                        policy_group = ACI_OBJECTS['LEAF_POLICY_GROUP'].format(policy_group_speed, policy_group_neg)
                        policy_group_exists = apic.aci_get_leaf_access_port_policy_grp(policy_group)
                        if policy_group_exists[0] == 0:
                            if not policy_group_exists[1]:
                                msg = 'ERROR: ACI policy group {0} not present on ACI fabric.'.format(policy_group)
                                error_msgs.append(msg)
                        else:
                            msg = 'ERROR: ACI query failed.'
                            error_msgs.append(msg)

                    # Check if interface selector exists and portblks assigned.
                    selector_range = []
                    if aci_fex_id:
                        selector_exists = apic.aci_get_interface_selector_fex(interface_profile, interface_selector)
                    else:
                        selector_exists = apic.aci_get_interface_selector(interface_profile, interface_selector)

                    if selector_exists[0] == 0:
                        if selector_exists[1]:
                            for child in selector_exists[2]:
                                port_blk = child['infraPortBlk']['attributes']
                                port_from = int(port_blk['fromPort'])
                                port_to = int(port_blk['toPort']) + 1
                                port_range = range(port_from, port_to)
                                if selector_range:
                                    selector_range += port_range
                                else:
                                    selector_range = port_range
                    # if selector_range is empty [] then we haven't configured it, but need to check if someone else has!
                    if not selector_range:
                    # Check ACI ports not already used.
                        for switch_profile, port_dict in switch_ports.items():
                            if aci_node in port_dict['nodes']:
                                if aci_fex_id in port_dict:
                                    if aci_port in port_dict[aci_fex_id]:
                                        msg = 'ERROR: ACI port {} on node {} fex {} already assigned.'.format(aci_port, aci_node, aci_fex_id)
                                        error_msgs.append(msg)
                    else:
                        if len(selector_range) > 1:
                            msg = 'ERROR: Too many ports {1} assigned to {0}.'.format(interface_selector, selector_range)
                            error_msgs.append(msg)
                        else:
                            # eg if selector_range = [35] and aci_port = 35, then it is set correctly.
                            if str(selector_range[0]) != aci_port:
                                msg = 'ERROR: {0} has incorrect portblk {1}.'.format(interface_selector, selector_range)
                                error_msgs.append(msg)

                    # Write status message per interface in migration.
                    msg = template.format(migration_id,
                                          device_name,
                                          interface,
                                          aci_node,
                                          aci_fex_id,
                                          aci_interface,
                                          policy_group,
                                          link_level_policy,
                                          )
                    msgs.append(msg)
                    # Add interface args to aci_config_args dictionary
                    aci_config_args['interface'].append({'node': aci_node,
                                                         'aci_fex_id': aci_fex_id,
                                                         'vpc_nodes': vpc_nodes,
                                                         'vpc_fexes': vpc_fexes,
                                                         'port': aci_port,
                                                         'policy_group': policy_group,
                                                         'link_level_policy': link_level_policy,
                                                         'is_trunk': trunk,
                                                         'channel': channel_type,
                                                         'interface_profile': interface_profile,
                                                         'interface_selector': interface_selector,
                                                         'interface_description': interface_description,
                                                         'bindings': bindings})

            aci_config_args['bindings'] = bindings_in_migration

            apic.disconnect()
        else:
            msg = 'ERROR: Empty migration {0}'.format(migration_id)
            error_msgs.append(msg)

    else:
        msg = 'ERROR: Migration {0} not found.'.format(migration_id)
        error_msgs.append(msg)
    if error_msgs:
        return_code = 1
    else:
        return_code = 0
    return {'rc': return_code, 'info': msgs, 'warning': warning_msgs, 'error': error_msgs, 'config': aci_config_args}


def aci_configure(migration_id, aci_config_args, tasks):
    fabric = aci_config_args['fabric']        
    apic = evoACI.Apic()
    apic.login(fabric)
    if not apic.can_connect:
        sys.exit('ERROR: Failed to connect to any APIC in Fabric {0}'.format(fabric))

    vrf = aci_config_args['vrf']
    pdom = aci_config_args['pdom']
    l3_out = aci_config_args['l3_out']
    tenant = aci_config_args['tenant']
    bd_tenant = aci_config_args['bd_tenant']
    vrf_tenant = aci_config_args['vrf_tenant']
    ap = aci_config_args['ap']
    msgs = []
    error_msgs = []
    if 'fabric' in tasks:
        total = len(aci_config_args['interface'])
        count = 0
        print
        for interface in aci_config_args['interface']:
            count += 1
            msg = 'INFO: Configuring fabric for interface {0:03d} out of {1:03d}.'.format(count, total)
            sys.stdout.write(msg)
            sys.stdout.flush()
            for back in range(0, len(msg)):
                sys.stdout.write('\b')

            interface_profile = interface['interface_profile']
            interface_selector = interface['interface_selector']
            interface_description = interface['interface_description']
            aci_fex_id = interface['aci_fex_id']
            port = interface['port']
            policy_group = interface['policy_group']
            # Single non-channel interface
            if interface['channel'] == 'single':
                # Configure Interface Selector
                if aci_fex_id == 'local':
                    object_exists = apic.aci_get_interface_selector(interface_profile, interface_selector)
                else:
                    object_exists = apic.aci_get_interface_selector_fex(interface_profile, interface_selector)

                if object_exists[0] == 0:
                    if object_exists[1]:
                        msg = 'INFO: {0} {1} in {2} {3} present on ACI fabric.'.format('Interface Selector', interface_selector,
                                                                                       'Interface Profile', interface_profile)
                        msgs.append(msg)
                    else:
                        if aci_fex_id == 'local':
                            object_conf = apic.aci_set_interface_selector(interface_profile, interface_selector, port,
                                                                          policy_group, interface_description)
                        else:
                            object_conf = apic.aci_set_interface_selector_fex(interface_profile, aci_fex_id, interface_selector, 
                                                                              port, policy_group, interface_description)
                        if object_conf[0] == 0:
                            msg = 'INFO: {0} {1} in {2} {3} configured on ACI fabric.'.format('Interface Selector', interface_selector,
                                                                                              'Interface Profile', interface_profile)
                            msgs.append(msg)
                        else:
                            msg = 'ERROR: {0}'.format(object_conf[2])
                            error_msgs.append(msg)

            # Port-channel or LAG
            if interface['channel'] == 'lag':
                # Configure Interface Selector
                object_exists = apic.aci_get_interface_selector(interface_profile, interface_selector)
                if object_exists[0] == 0:
                    if object_exists[1]:
                        msg = 'INFO: {0} {1} in {2} {3} present on ACI fabric.'.format('Interface Selector', interface_selector,
                                                                                       'Interface Profile', interface_profile)
                        msgs.append(msg)
                    else:
                        object_conf = apic.aci_set_interface_selector_vpc(interface_profile, interface_selector, port,
                                                                          policy_group)
                        if object_conf[0] == 0:
                            msg = 'INFO: {0} {1} in {2} {3} configured on ACI fabric.'.format('Interface Selector', interface_selector,
                                                                                              'Interface Profile', interface_profile)
                            msgs.append(msg)
                        else:
                            msg = 'ERROR: {0}'.format(object_conf[2])
                            error_msgs.append(msg)

                # Configure PC Policy Group
                aep = aci_config_args['aep']
                ll_policy = interface['link_level_policy']
                cdp_policy = aci_config_args['cdp_policy']
                mcp_policy = aci_config_args['mcp_policy']
                lldp_policy = aci_config_args['lldp_policy']
                stp_policy = aci_config_args['stp_policy']
                lacp_policy = aci_config_args['lacp_policy']
                object_exists = apic.aci_get_vpc_policy_grp(policy_group)
                if object_exists[0] == 0:
                    if object_exists[1]:
                        msg = 'INFO: {0} {1} present on ACI fabric.'.format('PC Policy Group', policy_group)
                        msgs.append(msg)
                    else:
                        object_conf = apic.aci_set_pc_policy_grp(policy_group, aep, ll_policy, cdp_policy, mcp_policy,
                                                                 lldp_policy, stp_policy, lacp_policy)
                        if object_conf[0] == 0:
                            msg = 'INFO: {0} {1} configured on ACI fabric.'.format('PC Policy Group', policy_group)
                            msgs.append(msg)
                        else:
                            msg = 'ERROR: {0}'.format(object_conf[2])
                            error_msgs.append(msg)
            # Virtual Port-channel or MLAG
            if interface['channel'] == 'vpc':
                if aci_fex_id == 'local':
                    object_exists = apic.aci_get_interface_selector(interface_profile, interface_selector)
                else:
                    object_exists = apic.aci_get_interface_selector_fex(interface_profile, interface_selector)

                # Configure Interface Selector
                if object_exists[0] == 0:
                    if object_exists[1]:
                        msg = 'INFO: {0} {1} present on ACI fabric.'.format('Interface Selector', interface_selector)
                        msgs.append(msg)
                    else:
                        if aci_fex_id == 'local':
                            object_conf = apic.aci_set_interface_selector_vpc(interface_profile, interface_selector, port,
                                                                              policy_group)
                        else:
                            object_conf = apic.aci_set_interface_selector_vpc_fex(interface_profile, aci_fex_id, interface_selector, port,
                                                                              policy_group)
                        if object_conf[0] == 0:
                            msg = 'INFO: {0} {1} configured on ACI fabric.'.format('Interface Selector', interface_selector)
                            msgs.append(msg)
                        else:
                            msg = 'ERROR: {0}'.format(object_conf[2])
                            error_msgs.append(msg)
                # Configure VPC Policy Group
                aep = aci_config_args['aep']
                ll_policy = interface['link_level_policy']
                cdp_policy = aci_config_args['cdp_policy']
                mcp_policy = aci_config_args['mcp_policy']
                lldp_policy = aci_config_args['lldp_policy']
                stp_policy = aci_config_args['stp_policy']
                lacp_policy = aci_config_args['lacp_policy']
                object_exists = apic.aci_get_vpc_policy_grp(policy_group)
                if object_exists[0] == 0:
                    if object_exists[1]:
                        msg = 'INFO: {0} {1} present on ACI fabric.'.format('VPC Policy Group', policy_group)
                        msgs.append(msg)
                    else:
                        object_conf = apic.aci_set_vpc_policy_grp(policy_group, aep, ll_policy, cdp_policy, mcp_policy,
                                                                 lldp_policy, stp_policy, lacp_policy)
                        if object_conf[0] == 0:
                            msg = 'INFO: {0} {1} configured on ACI fabric.'.format('VPC Policy Group', policy_group)
                            msgs.append(msg)
                        else:
                            msg = 'ERROR: {0}'.format(object_conf[2])
                            error_msgs.append(msg)
        if error_msgs:
            return [1, msgs, error_msgs]

    if 'tenant' in tasks:
        total = len(aci_config_args['bindings'])
        count = 0
        print
        for binding in aci_config_args['bindings']:
            count += 1
            msg = 'INFO: Configuring Tenant objects {0:03d} out of {1:03d}.'.format(count, total) 
            sys.stdout.write(msg)
            sys.stdout.flush()
            for back in range(0, len(msg)):
                sys.stdout.write('\b')

            bd = binding['bd']
            descr = binding['vlan_name']
            object_exists = apic.aci_get_bd(bd, bd_tenant)
            if object_exists[0] == 0:
                if object_exists[1]:
                    msg = 'INFO: {0} {1} present on ACI fabric.'.format('Bridge Domain', bd)
                    msgs.append(msg)
                else:
                    object_conf = apic.aci_set_bd(bd, bd_tenant, vrf, l3_out, descr)
                    if object_conf[0] == 0:
                        msg = 'INFO: {0} {1} configured on ACI fabric.'.format('Bridge Domain', bd)
                        msgs.append(msg)
                    else:
                        msg = 'ERROR: {0}'.format(object_conf[2])
                        error_msgs.append(msg)
            epg = binding['epg']
            object_exists = apic.aci_get_epg(epg, tenant, ap)
            if object_exists[0] == 0:
                if object_exists[1]:
                    msg = 'INFO: {0} {1} present on ACI fabric.'.format('EPG', epg)
                    msgs.append(msg)
                else:
                    object_conf = apic.aci_set_epg(epg, tenant, ap, bd, pdom, descr)
                    if object_conf[0] == 0:
                        msg = 'INFO: {0} {1} configured on ACI fabric.'.format('EPG', epg)
                        msgs.append(msg)
                    else:
                        msg = 'ERROR: {0}'.format(object_conf[2])
                        error_msgs.append(msg)
        if error_msgs:
            return [1, msgs, error_msgs]

    if 'bindings' in tasks:
        pod = '1'
        total = len(aci_config_args['interface'])
        count = 0
        print
        for interface in aci_config_args['interface']:
            count += 1
            msg = 'INFO: Configuring bindings for interface {0:03d} out of {1:03d}.'.format(count, total)
            sys.stdout.write(msg)
            sys.stdout.flush()
            for back in range(0, len(msg)):
                sys.stdout.write('\b')

            node = interface['node']
            aci_fex_id = interface['aci_fex_id']
            port = interface['port']
            trunk = interface['is_trunk']
            policy_group = interface['policy_group']
            interface_selector = interface['interface_selector']
            interface_profile = interface['interface_profile']
            vpc_nodes = interface['vpc_nodes']
            vpc_fexes = interface['vpc_fexes']
            if aci_fex_id == 'local':
                object_exists = apic.aci_get_interface_selector(interface_profile, interface_selector)
            else:
                object_exists = apic.aci_get_interface_selector_fex(interface_profile, interface_selector)
            if object_exists[0] == 0:
                if object_exists[1]:
                    for vlan, bindings in interface['bindings'].items():
                        epg = bindings['epg']
                        epg_exists = apic.aci_get_epg(epg, tenant, ap)
                        if epg_exists[0] == 0:
                            if epg_exists[1]:
                                if interface['channel'] == 'single':
                                    path = 'eth1/' + port
                                    object_exists = apic.aci_get_static_binding(tenant, ap, epg, pod, node, aci_fex_id, port, vlan)
                                    if object_exists[0] == 0:
                                        if object_exists[1]:
                                            msg = 'INFO: {0} tn-{1} ap-{2} epg-{3} pathep-[{4}] present on ACI fabric.'.format('Static Binding', tenant, ap, epg, path)
                                            msgs.append(msg)
                                        else:
                                            if aci_fex_id == 'local':
                                                object_conf = apic.aci_set_static_binding(tenant, ap, epg, pod, node,
                                                                                          port, vlan, trunk)
                                            else:
                                                object_conf = apic.aci_set_static_binding_fex(tenant, ap, epg, pod,
                                                                                              node, aci_fex_id, port,
                                                                                              vlan, trunk)
                                            if object_conf[0] == 0:
                                                msg = 'INFO: {0} tn-{1} ap-{2} epg-{3} pathep-[{4}] configured on ACI fabric.'.format('Static Binding', tenant, ap, epg, path)
                                                msgs.append(msg)
                                            else:
                                                msg = 'ERROR: {0}'.format(object_conf[2])
                                                error_msgs.append(msg)

                                elif interface['channel'] == 'lag':
                                    path = policy_group
                                    object_exists = apic.aci_get_static_binding(path, tenant, ap, epg, vlan)
                                    if object_exists[0] == 0:
                                        if object_exists[1]:
                                            msg = 'INFO: {0} tn-{1} ap-{2} epg-{3} pathep-[{4}] present on ACI fabric.'.format('Static Binding', tenant, ap, epg, path)
                                            msgs.append(msg)
                                        else:
                                            object_conf = apic.aci_set_static_binding_pc(tenant, ap, epg, pod, node, policy_group, vlan, trunk)
                                            if object_conf[0] == 0:
                                                msg = 'INFO: {0} tn-{1} ap-{2} epg-{3} pathep-[{4}] configured on ACI fabric.'.format('PC Static Binding', tenant, ap, epg, path)
                                                msgs.append(msg)
                                            else:
                                                msg = 'ERROR: {0}'.format(object_conf[2])
                                                error_msgs.append(msg)

                                elif interface['channel'] == 'vpc':
                                    path = policy_group
                                    if aci_fex_id == 'local':
                                        object_exists = apic.aci_get_static_binding_vpc(tenant, ap, epg, pod, vpc_nodes, policy_group, vlan)
                                    else:
                                        object_exists = apic.aci_get_static_binding_vpc_fex(tenant, ap, epg, pod, vpc_nodes, vpc_fexes, policy_group, vlan)
                                    if object_exists[0] == 0:
                                        if object_exists[1]:
                                            msg = 'INFO: {0} tn-{1} ap-{2} epg-{3} pathep-[{4}] present on ACI fabric.'.format('Static Binding', tenant, ap, epg, path)
                                            msgs.append(msg)
                                        else:
                                            if aci_fex_id == 'local':
                                                object_conf = apic.aci_set_static_binding_vpc(tenant, ap, epg, pod, vpc_nodes, policy_group, vlan, trunk)
                                            else:
                                                object_conf = apic.aci_set_static_binding_vpc_fex(tenant, ap, epg, pod, vpc_nodes, vpc_fexes, policy_group, vlan, trunk)
                                            if object_conf[0] == 0:
                                                msg = 'INFO: {0} tn-{1} ap-{2} epg-{3} pathep-[{4}] configured on ACI fabric.'.format('VPC Static Binding', tenant, ap, epg, path)
                                                msgs.append(msg)
                                            else:
                                                msg = 'ERROR: {0}'.format(object_conf[2])
                                                error_msgs.append(msg)
                                    else:
                                        name = "tn-{0} ap-{1} epg-{2} pathep-[{3}]".format(tenant, ap, epg, path)
                                        msg = 'ERROR: Query for {} on ACI fabric failed.'.format(name)
                                        error_msgs.append(msg)
                            else:
                                msg = 'INFO: EPG {} not present.'.format(epg)
                                if msg not in error_msgs:
                                    error_msgs.append(msg)
                        else:
                            msg = 'ERROR: Query for {} on ACI fabric failed.'.format(epg)
                            error_msgs.append(msg)
                else:
                    msg = 'ERROR: Interface Selector {0} not present in Interface Profile {1}.'.format(interface_selector, interface_profile)
                    error_msgs.append(msg)
            else:
                msg = 'ERROR: Query for {} on ACI fabric failed.'.format(interface_selector)
                error_msgs.append(msg)


        if error_msgs:
            return [1, msgs, error_msgs]

    if 'bd_subnets' in tasks:
        tenant_exists = apic.aci_get_tenant(bd_tenant)
        if tenant_exists[0] == 0:
            if tenant_exists[1]:
                total = len(aci_config_args['bindings'])
                count = 0
                print
                for binding in aci_config_args['bindings']:
                    count += 1
                    msg = 'INFO: Configuring BD subnets {0:03d} out of {1:03d}.'.format(count, total)
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                    for back in range(0, len(msg)):
                        sys.stdout.write('\b')

                    bd = binding['bd']
                    gateway = binding['gateway']
                    vmac = binding['vmac']
                    bd_exists = apic.aci_get_bd(bd, bd_tenant)
                    if bd_exists[0] == 0:
                        if bd_exists[1]:
                            if gateway:
                                bd_subnet_exists = apic.aci_get_bd_subnet(bd, bd_tenant, gateway)
                                if bd_subnet_exists[0] == 0:
                                    if bd_subnet_exists[1]:
                                        msg = 'INFO: {0} {1} {2} {3} present on ACI fabric.'.format('Bridge Domain', bd, 'Subnet', gateway)
                                        msgs.append(msg)
                                    else:
                                        object_conf = apic.aci_set_bd_subnet(bd, bd_tenant, gateway, l3_out)
                                        if object_conf[0] == 0:
                                            msg = 'INFO: {0} {1} {2} {3} configured on ACI fabric.'.format('Bridge Domain', bd, 'Subnet', gateway)
                                            msgs.append(msg)
                                    # Set MAC
                                    bd_mac_exists = apic.aci_get_bd_mac(bd, bd_tenant, vmac)
                                    if bd_mac_exists[0] == 0:
                                        if bd_mac_exists[1]:
                                            msg = 'INFO: {0} {1} {2} {3} present on ACI fabric.'.format('Bridge Domain', bd, 'MAC', vmac)
                                            msgs.append(msg)
                                        else:
                                            object_conf = apic.aci_set_bd_mac(bd, bd_tenant, vmac)
                                            if object_conf[0] == 0:
                                                msg = 'INFO: {0} {1} {2} {3} configured on ACI fabric.'.format('Bridge Domain', bd, 'MAC', vmac)
                                                msgs.append(msg)
                                            else:
                                                msg = 'ERROR: {0}'.format(object_conf[2])
                                                error_msgs.append(msg)        
                                    else:
                                        msg = 'ERROR: Query for {} on ACI fabric failed.'.format(vmac)
                                        error_msgs.append(msg)
                                    # Set unkMacUcastAct to proxy
                                    object_conf = apic.aci_set_bd_MacUcastAct(bd, bd_tenant)
                                    if object_conf[0] == 0:
                                        msg = 'INFO: {0} {1} {2} configured on ACI fabric.'.format('Bridge Domain', bd, 'Unknown mac unicast flood proxy')
                                        msgs.append(msg)
                                    else:
                                        msg = 'ERROR: {0}'.format(object_conf[2])
                                        error_msgs.append(msg)
                                else:
                                    msg = 'ERROR: Query for {} on ACI fabric failed.'.format(gateway)
                                    error_msgs.append(msg)
                            else:
                                msg = 'INFO: Bridge Domain Subnet not configured, no gateway for {}'.format(bd)
                                msgs.append(msg)
                        else:
                            msg = 'ERROR: Bridge Domain {} not present on ACI fabric.'.format(bd)
                            error_msgs.append(msg)
                    else:
                        msg = 'ERROR: Query for {} on ACI fabric failed.'.format(bd)
                        error_msgs.append(msg)
            else:
                msg = 'ERROR: Tenant {} not present on ACI fabric.'.format(bd_tenant)
                error_msgs.append(msg)
        else:
            msg = 'ERROR: Query for {} on ACI fabric failed.'.format(bd_tenant)
            error_msgs.append(msg)
        if error_msgs:
            return [1, msgs, error_msgs]

    if 'arp_flood_off' in tasks:
        tenant_exists = apic.aci_get_tenant(bd_tenant)
        if tenant_exists[0] == 0:
            if tenant_exists[1]:
                for binding in aci_config_args['bindings']:
                    gateway = binding['gateway']
                    if gateway:
                        bd = binding['bd']
                        bd_exists = apic.aci_get_bd(bd, bd_tenant)
                        if bd_exists[0] == 0:
                            if bd_exists[1]:
                                flood_set = apic.aci_get_bd_arpflood(bd, 'common', arp_flood='no')
                                if flood_set[0] == 0:
                                    if not flood_set[1]:
                                        flood_conf = apic.aci_set_bd_arpflood(bd, 'common', arp_flood='no')
                                        if flood_conf[0] == 0:
                                            msg = 'INFO: Bridge Domain {} set to arp_flood="no".'.format(bd)
                                            msgs.append(msg)
                                        else:
                                            msg = 'ERROR: Bridge Domain {} arp_flood not set.'.format(bd)
                                            error_msgs.append(msg)
                                else:
                                    msg = 'ERROR: Query for {} arp_flood on ACI fabric failed.'.format(bd)
                                    error_msgs.append(msg)
                            else:
                                msg = 'ERROR: Bridge Domain {} not present on ACI fabric.'.format(bd)
                                error_msgs.append(msg)
                        else:
                            msg = 'ERROR: Query for {} on ACI fabric failed.'.format(bd)
                            error_msgs.append(msg)
            else:
                msg = 'ERROR: Tenant {} not present on ACI fabric.'.format(bd_tenant)
                error_msgs.append(msg)
        else:
            msg = 'ERROR: Query for {} on ACI fabric failed.'.format(bd_tenant)
            error_msgs.append(msg)
        if error_msgs:
            return [1, msgs, error_msgs]

    elif 'arp_flood_on' in tasks:
        tenant_exists = apic.aci_get_tenant(bd_tenant)
        if tenant_exists[0] == 0:
            if tenant_exists[1]:
                for binding in aci_config_args['bindings']:
                    gateway = binding['gateway']
                    if gateway:
                        bd = binding['bd']
                        bd_exists = apic.aci_get_bd(bd, bd_tenant)
                        if bd_exists[0] == 0:
                            if bd_exists[1]:
                                flood_set = apic.aci_get_bd_arpflood(bd, 'common', arp_flood='yes')
                                if flood_set[0] == 0:
                                    if not flood_set[1]:
                                        flood_conf = apic.aci_set_bd_arpflood(bd, 'common', arp_flood='yes')
                                        if flood_conf[0] == 0:
                                            msg = 'INFO: Bridge Domain {} set to arp_flood="yes".'.format(bd)
                                            msgs.append(msg)
                                        else:
                                            msg = 'ERROR: Bridge Domain {} arp_flood not set.'.format(bd)
                                            error_msgs.append(msg)
                                else:
                                    msg = 'ERROR: Query for {} arp_flood on ACI fabric failed.'.format(bd)
                                    error_msgs.append(msg)
                            else:
                                msg = 'ERROR: Bridge Domain {} not present on ACI fabric.'.format(bd)
                                error_msgs.append(msg)
                        else:
                            msg = 'ERROR: Query for {} on ACI fabric failed.'.format(bd)
                            error_msgs.append(msg)
            else:
                msg = 'ERROR: Tenant {} not present on ACI fabric.'.format(bd_tenant)
                error_msgs.append(msg)
        else:
            msg = 'ERROR: Query for {} on ACI fabric failed.'.format(bd_tenant)
            error_msgs.append(msg)
        if error_msgs:
            return [1, msgs, error_msgs]

    return [0, msgs, error_msgs]


def aci_prepare_fabric():
    apic = evoACI.Apic()
    apic.login('CiscoSVS')
    #
    # Fabric Functions
    #
    print 'set_vlan_pool:', apic.aci_set_vlan_pool('VLANP_2-4000', 2, 4000, delete=False)
    print 'set_pdom:', apic.aci_set_pdom('PDOM_GLOBAL', 'VLANP_2-4000', delete=False)
    print 'set_aep:', apic.aci_set_aep('AEP_COMPUTE', 'PDOM_GLOBAL', delete=False)
    print 'set_switch_profile:', apic.aci_set_switch_profile('LEAF_220', 'SS_220', '220')
    print 'get_switch_profile:', apic.aci_get_switch_profile('LEAF_220')
    print 'set_switch_profile:', apic.aci_set_switch_profile('LEAF_221', 'SS_221', '221')
    print 'get_switch_profile:', apic.aci_get_switch_profile('LEAF_221')
    print 'set_switch_profile:', apic.aci_set_switch_profile('LEAF_222', 'SS_222', '222')
    print 'get_switch_profile:', apic.aci_get_switch_profile('LEAF_222')
    print 'set_switch_profile:', apic.aci_set_switch_profile('LEAF_223', 'SS_223', '223')
    print 'get_switch_profile:', apic.aci_get_switch_profile('LEAF_223')
    #
    print 'set_interface_profile:', apic.aci_set_interface_profile('IP_LEAF_220')
    print 'get_interface_profile:', apic.aci_get_interface_profile('IP_LEAF_220')
    print 'set_interface_profile:', apic.aci_set_interface_profile('IP_LEAF_221')
    print 'get_interface_profile:', apic.aci_get_interface_profile('IP_LEAF_221')
    print 'set_interface_profile:', apic.aci_set_interface_profile('IP_LEAF_222')
    print 'get_interface_profile:', apic.aci_get_interface_profile('IP_LEAF_222')
    print 'set_interface_profile:', apic.aci_set_interface_profile('IP_LEAF_223')
    print 'get_interface_profile:', apic.aci_get_interface_profile('IP_LEAF_223')
    #
    print 'set_switch_interface_profile_association:', apic.aci_set_switch_interface_profile_association('LEAF_220', 'IP_LEAF_220')
    print 'set_switch_interface_profile_association:', apic.aci_set_switch_interface_profile_association('LEAF_221', 'IP_LEAF_221')
    print 'set_switch_interface_profile_association:', apic.aci_set_switch_interface_profile_association('LEAF_222', 'IP_LEAF_222')
    print 'set_switch_interface_profile_association:', apic.aci_set_switch_interface_profile_association('LEAF_223', 'IP_LEAF_223')
    #
    print 'set_link_level_policy:', apic.aci_set_link_level_policy('1gig_auto', '1G', 'on')
    print 'set_cdp_policy:', apic.aci_set_cdp_policy('cdp_enabled', 'enabled')
    print 'set_mcp_policy:', apic.aci_set_mcp_policy('mcp_enabled', 'enabled')
    print 'set_lldp_policy:', apic.aci_set_lldp_policy('lldp_enabled', 'enabled')
    print 'set_stp_policy:', apic.aci_set_stp_policy('default', 'disabled', 'disabled')
    print 'set_port_chanel_policy:', apic.aci_set_port_channel_policy('static_on', 'static')
    print 'set_port_channel_policy:', apic.aci_set_port_channel_policy('lacp_active', 'active')
    print 'set_port_channel_policy:', apic.aci_set_port_channel_policy('lacp_passive', 'passive')

    #
    # Tenant Functions
    #
    print 'set_vrf:', apic.aci_set_vrf('VRF_GLOBAL', 'common')
    print 'get_vrf:', apic.aci_get_vrf('VRF_GLOBAL', 'common')
    print 'set_vrf:', apic.aci_set_vrf('VRF_FEN', 'common')
    print 'get_vrf:', apic.aci_get_vrf('VRF_FEN', 'common')
    #
    print 'set_l3o:', apic.aci_set_l3o('L3OUT_FEN', 'EPG_L3OUT_FEN', 'common')
    print 'get_l3o:', apic.aci_get_l3o('L3OUT_FEN', 'common')
    print 'set_bd:', apic.aci_set_bd('BD_10.10.10.0', 'common', 'VRF_FEN', 'L3OUT_FEN')
    print 'get_bd:', apic.aci_get_bd('BD_10.10.10.0', 'common')
    print 'set_tenant:', apic.aci_set_tenant('MIXED')
    print 'get_tenant:', apic.aci_get_tenant('MIXED')
    print 'set_app:', apic.aci_set_app('AP_Mixed', 'MIXED')
    print 'get_app:', apic.aci_get_app('AP_Mixed', 'MIXED')

    apic.disconnect()


def main():
    parser = argparse.ArgumentParser(description="Manage ACI migrations.")
    subparsers = parser.add_subparsers(help='Sub-command help', dest='subcommand')

    # import
    vrf_list = METADATA['ACI_OBJECTS']['VRF']
    parser_import = subparsers.add_parser("import", help="Import patching schedule.")
    parser_import.add_argument( "-file", help="Patching schedule (*.csv).")
    parser_import.add_argument( "-vrf", help="Target VRF for a migration.",
                                        choices=vrf_list, required=True)

    # manage
    parser_manage = subparsers.add_parser("manage", help="List, View, Delete migrations.")
    parser_manage.add_argument( "-list", help="List migrations.", action="store_true")
    parser_manage.add_argument( "-view", metavar="id", help="View migration info.")
    parser_manage.add_argument( "-delete", metavar="id", help="Delete migration.")

    # precheck
    parser_precheck = subparsers.add_parser("precheck", help="Pre-check DB, metadata and configuration.")
    parser_precheck.add_argument("id", help="Migration id")

    # print config
    parser_print_config = subparsers.add_parser("print_config", help="Print configuration arguments.")
    parser_print_config.add_argument("id", help="Migration id")

    # config
    parser_config = subparsers.add_parser("config", help="Configure ACI.")
    parser_config.add_argument("id", help="Migration id.")
    parser_config.add_argument("-tasks", choices=["fabric","tenant", "bd_subnets", "bindings", "arp_flood_off", "arp_flood_on"],
                                         help="Perform ACI Configuration tasks, one or many.",
                                         nargs="+",
                                         required=True)
    # dev
    #parser_dev = subparsers.add_parser("dev", help="Prepare.")
    #parser_dev.add_argument( "-prepare", help="Prepare Fabric.", action="store_true")

    args = parser.parse_args()

    if args.subcommand == 'import':
        if args.file:
            migration_descr = raw_input('Enter Description (32 char):')
            result = load_patching_file_xlsx(args.file, args.vrf, migration_descr)
            if result[0] == 0:
                print 'Migration {0} created using file {1}.'.format(result[1], args.file)
            else:
                for msg in result[1]:
                    print msg
                for msg in result[2]:
                    print msg
        else:
            print 'ERROR: -file argument must be supplied.'

    elif args.subcommand == 'manage':
        if args.list:
            list_migrations()
        elif args.view:
            view_migration(args.view)
        elif args.delete:
            set_migration_status(args.id, status='deleted')

    elif args.subcommand == 'precheck':
        status = get_migration_status(args.id)
        if status[0] == 0:
            if status[1] == 'CONFIGURED':
                print 'ERROR: Cannot run pre-checks after configuration.'
            else:
                # Remove previous prechek data
                delete_config_args(args.id)
                result = aci_precheck(args.id)
                if result['rc'] == 0:
                    for msg in result['info']:
                        print msg
                    for msg in result['warning']:
                        print msg
                    print 'Migration {0} precheck ok.'.format(args.id)
                    aci_config_args = result['config']
                    save_config_args(args.id, aci_config_args)
                else:
                    for msg in result['info']:
                        print msg
                    for msg in result['warning']:
                        print msg
                    for msg in result['error']:
                        print msg
        else:
            print 'ERROR: Status unknown for Migration {}.'.format(args.id)

    elif args.subcommand == 'print_config':
        config_args = get_config_args(args.id)
        if config_args[0] == 0:
            pprint.pprint(config_args[1])
        else:
            print 'ERROR: No configuration arguments, run precheck.'


    elif args.subcommand == 'config':
        config_args = get_config_args(args.id)
        if config_args[0] == 0:
            conf_result = aci_configure(args.id, config_args[1], args.tasks)
            if conf_result[0] == 0:
                set_migration_status(args.id, status='configured')
                for msg in conf_result[1]:
                    print msg
                print 'INFO: Configuration applied to ACI fabric.'
            else:
                for msg in conf_result[1]:
                    print msg
                for error_msg in conf_result[2]:
                    print error_msg
                print 'ERROR: Configuration not applied to ACI fabric.'
        else:
            print 'ERROR: No configuration arguments, run precheck.'

    elif args.subcommand == 'dev':
        if args.prepare:
            aci_prepare_fabric()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
