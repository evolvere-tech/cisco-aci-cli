# Description

The ACLI is a command line shell for Cisco ACI APIC. A set of commands was developed to return information which is difficult to get through the GUI interface.

# Installation

## Docker

    docker run -it --rm evolvere/cisco-aci

If you would like to use a local settings file, copy from repository and amend, then:

    docker run -it --rm -v /tmp/settings:/cisco-aci/settings evolvere/cisco-aci

where local settings file is /tmp/settings/aci_settings.py

## Environment

Required

* Python 2.7+
* Cobra SDK (http://cobra.readthedocs.io/en/latest/)
* PrettyTable

## Downloading

If you have git installed, clone the repository

    git clone https://github.com/evolvere-tech/cisco-aci.git

## Installation

Script doesn't require installation and can be invoked directly:

	python acli.py

File settings/aci_settings.py needs to be amended prior running the script with respective credentials for APIC controllers. Multiple fabrics are supported by the script: if either username or password are not specified the script will request the login credentials.

# Usage

Script supports help command, auto completion for commands and auto-completes list of EPGs and list of Leaf Nodes.


## Login

To connect to APIC in target Fabric use login command:

	login [FABRIC_NAME]

Script will try all the APICs in the aci_settings file in round-robin. No need to logout, run login again to switch to another Fabric.

## Show commands

	show epg [epg_name]

Outputs EPG information along with static bindings, status of physical interfaces, interface selectors and port policy groups for all EPGs or for selected EPG (EPG names are auto-completed by using 'TAB').

	show interface [node] [interface]

Collects status of physical interfaces on Leaf switches and related fabric configuration (port selectors, policy groups). If node and interface options specified then shell returns EPG mappings for the target interface. 

	show vlan <vlan_id> | pool

Shows VLAN pools and associated Physical/Virtual Domains. If VLAN_ID option is supplied the script will return any associated Pools and EPGs.

	show snapshot

Shows all snapshots including Description field, which is not available via GUI.  See “config snapshot” further below to add/amend description for any existing snapshots or to create a new OneTime snapshot with a description. 


## Config commands

	config snapshot new | <snapshot_id>

Configuration command to create a new one time snapshot with description or add/amend description on existing one.


# License

Copyright 2016 Evolvere Technologies Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

