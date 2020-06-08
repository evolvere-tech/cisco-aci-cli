# Description

The ACLI is a command line shell for Cisco ACI APIC. A set of commands was developed to return information which is difficult to get through the GUI interface.

# Installation

## Environment

Required

* Python 2.7 or Python3.5 or later
* PrettyTable

## Downloading

If you have git installed, clone the repository

    git clone https://github.com/evolvere-tech/cisco-aci-cli.git

## Installation

Create a virtual env (optional):

    virtualenv venv
    source venv/bin/activate
    pip install -r requirements.txt

Script doesn't require installation and can be invoked directly:

	python acli.py

File config.yml needs to be amended prior running the script with respective credentials for APIC controllers. Multiple fabrics are supported by the script: if either username or password are not specified the script will prompt for the login credentials.

# Usage

Script supports help command, auto completion for commands and auto-completes list of EPGs and list of Leaf Nodes and Interface Policy Groups.


## Login

To connect to APIC in target Fabric use login command:

	login [FABRIC_NAME]

Script will try all the APICs in the aci_settings file in round-robin. No need to logout, run login again to switch to another Fabric.

## Show commands

	show epg [epg_name]

Displays EPG information along with static bindings, which includes status of physical interfaces, interface selectors and port policy groups for all EPGs or for selected EPG (EPG names are auto-completed by using 'TAB').

	show interface [node] [interface]

Displays status of physical interfaces on all or specified Leaf switches and corresponding interface selectors and policy groups. If both node and interface options specified then the tool returns EPG bindings for a target interface. Interfaces with assigned interface selectors and policy groups, but not binded to any EPG, are flagged with "*".

	show vlan <vlan_id> | pool

Displays VLAN pools and associated Physical/Virtual Domains. If VLAN_ID option is supplied the tool will return any associated Pools and EPGs, which contain bindings with that VLAN as encapsulation.

	show ipg [<ipg_name>]

Displays policies for all Interface Policy Groups (same as GUI, but showing all interface, port-channel and vpc policy groups together, sorted by a name). If IPG specified (IPG names auto-completed by pressing 'TAB'), then detailed information will be displayed for an IPG: policies and all interfaces this policy is mapped to.

	show snapshot
	
Displays all snapshots.  See “config snapshot” further below to add/amend description for any existing snapshots or to create a new OneTime snapshot.

## Config commands

	config snapshot new | <snapshot_id>

Configuration command to create a new one time snapshot with description or add/amend description on existing one.


# License

Copyright 2019 Evolvere Technologies Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

