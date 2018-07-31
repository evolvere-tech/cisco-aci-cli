---
ACI_OBJECTS:
  VLAN_POOL: 'VLANP_2-4000'
  PDOM: 'PDOM_GLOBAL'
  AEP: 'AEP_COMPUTE'
  SWITCH_PROFILE: 'LEAF_{}'
  INTERFACE_PROFILE: 'IP_LEAF_{}'
  INTERFACE_PROFILE_FEX: 'IP_LEAF_{0}_fex{1}'
  INTERFACE_SELECTOR_PREFIX: 'IS_Intf-{}'
  LEAF_POLICY_GROUP: 'IPG_AC_{0}_{1}'
  LINK_LEVEL_POLICY: '{0}_{1}'
  PC_POLICY_GROUP_PREFIX: 'IPG_PC'
  VPC_POLICY_GROUP_PREFIX: 'IPG_vPC'
  VRF:
    - 'VRF_GLOBAL'
    - 'VRF_HADOOP'
  L3_OUT: 'L3OUT_FEN'
  TENANT: 'MIXED'
  BD_TENANT: 'common'
  VRF_TENANT: 'common'
  AP: 'AP_Mixed'

VPC_POLICY:
  CDP_POLICY: 'cdp_enabled'
  MCP_POLICY: 'mcp_enabled'
  LLDP_POLICY: 'lldp_enabled'
  STP_POLICY: 'default'
  LACP_POLICY: 'lacp_active'

LINK_LEVEL_SPEED_MAP:
  1gig:
    - '1000'
    - 'a-1000'
    - '1G'
    - 'a-1G'
  10gig:
    - '10G'
    - 'a-10G'
  40gig:
    - '40G'

POLICY_GROUP_SPEED_MAP:
  1G:
    - '1000'
    - 'a-1000'
    - '1G'
    - 'a-1G'
  10G:
    - '10G'
    - 'a-10G'
  40G:
    - '40G'
