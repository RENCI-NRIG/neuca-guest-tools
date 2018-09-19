This software is intended to be installed into guest VM images that will be
instantiated by OpenStack installations that have been patched with the NEuca extensions.

VM images can be variants of RedHat (or derivatives, like Fedora and Centos) or Debian/Ubuntu;
other Linux/Unix distributions can be supported, but will require minor patching.
Code contributions are welcome!

Typically, installation will require mounting an existing VM image as a loopback device and
chroot'ing into it to perform the installation.

Prerequisites: python-2.6 or greater (but not python 3), python-ipaddr, python-netaddr,
               python-daemon, python-boto, and the Open-iSCSI initiator utilities.

To install (when not using the supplied RPM or DEB), simply execute the following command:

python setup.py install

Init scripts are provided for both Debian and Redhat variants;
check within the appropriately named directory, and install it "as appropriate."

After the image boots you can also use the following tools from command line:
 * neuca-netconf - to configure host networking
 * neuca-user-script - to retrieve initial user-specified post-boot script
 * neuca-all-user-scripts - to retrieve all user-specified post-boot scripts
 * neuca-run-scripts - to execute any newly created user-specified post-boot scripts
 * neuca-user-data - to retrieve full user data
 * neuca-get - to retrieve specific items from user data
 * neuca-routes - to show whether host has been specified as a router, and get all routes
 * neuca-get-public-ip - to show the public IP of the host
 * neuca-distro - to check distribution detection
 * neuca-version - to report the version of neuca in use
 * neuca - issues the help printed above

For more information visit https://geni-orca.renci.org


# Usage on chameleon
## Heat Template for creating COMET Cluster
This heat template creates 2 CentOs7 servers and configures COMET on them. User is required to create COMET Context via the python client in order for instances.

[comet_chameleon.yaml.txt](https://github.com/RENCI-NRIG/neuca-guest-tools/files/2398192/comet_chameleon.yaml.txt)

Alternatively below described manual procedure can be followed:
## Manual Installation of neuca-guest-tools
### Login as root to chameleon instance
### Install neuca-guest-tool dependencies
`pip install -U boto`
`pip install python-daemon==2.1.2`
### Fetch neuca-guest-tools code by following commands
`git clone https://github.com/RENCI-NRIG/neuca-guest-tools`
`cd neuca-guest-tools/neuca-py/`
Until code is merged to master, following command is needed to get the latest neuca tools
`git checkout br217`
### Install neuca-guest-tools
`python setup.py install`
### Start neuca-guest-tools
`python /usr/bin/neucad start -c`
### Verify neuca daemon is running
`ps -eaf | grep neuca`
The above command should depict an output like below:
`root      11133      1  2 14:12 ?        00:00:00 python /usr/bin/neucad start`

NOTE: neuca-guest-tools are now running on chameleon node. In order for pubkeys and etchost feature to work configure COMET for the chameleon node and update Chameleon node instance meta data.

### Updating Chameleon Instance Meta Data
Update Chameleon instance meta data from Openstack GUI to contain following parameters:

slice_id=< Context ID used while creating COMET Context >
reservation_id=<Key used while creating COMET Context, should be same for both pubkeys and etchosts context per instance>
comethost=https://13.59.255.221:8111/,https://18.218.34.48:8111/
slicecometreadtoken=<readToken used while creating COMET context, should be same for all Chameleon instances to be grouped>
slicecometwritetoken=< writeToken used while creating COMET context >
comethostsgroupread=all
comethostsgroupwrite=all
cometpubkeysgroupread=all
cometpubkeysgroupwrite=all

#### Update Meta Data via Nova Client
`nova meta <instance name> set <key1=value1>`
Note: Multiple key value pairs can be specified in a single command.
Pre-requisite for the above command is to source Openstack Environment available from [Chameleon Dashboard](https://chi.tacc.chameleoncloud.org/dashboard/project/api_access/openrc/)

`source CH-818348-openrc.sh`
`nova meta kthare10 set slice_id=2bb5f982-60e8-4e3e-bf9f-08619698127a reservation_id=2c93dae4-9fb6-4d2e-bae0-b404aa06e36b comethost=https://13.59.255.221:8111/,https://18.218.34.48:8111/ slicecometreadtoken=2bb5f982 slicecometwritetoken=2bb5f981 comethostsgroupread=all comethostsgroupwrite=all cometpubkeysgroupread=all cometpubkeysgroupwrite=all`


## Creating COMET context for chameleon node
Use [Python Comet Client](https://github.com/RENCI-NRIG/COMET-Client/tree/master/python-client ) to create COMET context.
### Create pubkeys context with value
`{"val_":"[{\"publicKey\":\"\"}]"}`

### Create etchost context with value
`{"val_":"[{\"hostName\":\"kthare10.novalocal\",\"ip\":\"\"}]"}`
NOTE: Replace kthare10.novalocal with hostname of Chameleon instance

### Example Commands
#### Hosts Context
`curl --insecure -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{"val_":"[{\"hostName\":\"kthare11.novalocal\",\"ip\":\"\"}]"}' 'https://13.59.255.221:8111/writeScope?contextID=2bb5f982-60e8-4e3e-bf9f-08619698127a&family=hostsall&Key=2c93dae4-9fb6-4d2e-bae0-b404aa06e399&readToken=2bb5f982&writeToken=2bb5f983'  --cacert /Users/komalthareja/comet/DigiCertCA.crt --cert /Users/komalthareja/comet/inno-hn_exogeni_net.pem --key /Users/komalthareja/comet/inno-hn_exogeni_net.key`

OR

`python3.6 comet_client.py -o create_family -t https://13.59.255.221:8111 -i 04700364-ec9b-4958-b726-b063754a9143 -r 361a67ac -w 7b1c4d09 -f hostsall -k aa491da3-3f23-4a5a-9b9e-33f98884570b -v {"val_":"[{\"hostName\":\"kthare11.novalocal\",\"ip\":\"\"}]"} -a /Users/komalthareja/comet/DigiCertCA.crt -c /Users/komalthareja/comet/inno-hn_exogeni_net.pem -p /Users/komalthareja/comet/inno-hn_exogeni_net.key`

#### PubKeys Context
`curl --insecure -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{"val_":"[{\"publicKey\":\"\"}]"}' 'https://13.59.255.221:8111/writeScope?contextID=2bb5f982-60e8-4e3e-bf9f-08619698127a&family=pubkeysall&Key=2c93dae4-9fb6-4d2e-bae0-b404aa06e399&readToken=2bb5f982&writeToken=2bb5f983'  --cacert /Users/komalthareja/comet/DigiCertCA.crt --cert /Users/komalthareja/comet/inno-hn_exogeni_net.pem --key /Users/komalthareja/comet/inno-hn_exogeni_net.key`

OR

`python3.6 comet_client.py -o create_family -t https://13.59.255.221:8111 -i 04700364-ec9b-4958-b726-b063754a9143 -r 361a67ac -w 7b1c4d09 -f pubkeysall -k aa491da3-3f23-4a5a-9b9e-33f98884570b -v {"val_":"[{\"publicKey\":\"\"}]"} -a /Users/komalthareja/comet/DigiCertCA.crt -c /Users/komalthareja/comet/inno-hn_exogeni_net.pem -p /Users/komalthareja/comet/inno-hn_exogeni_net.key`

# Usage on exogeni nodes
## Fetch neuca-guest-tools code by following commands
`git clone https://github.com/RENCI-NRIG/neuca-guest-tools`
`cd neuca-guest-tools/neuca-py/`
Until code is merged to master, following command is needed to get the latest neuca tools
`git checkout br217`


## Install neuca-guest-tools
`python setup.py install`

Start neuca-guest-tools
`python /usr/bin/neucad restart`

## Verify neuca daemon is running
`ps -eaf | grep neuca`

The above command should depict an output like below:
`root 11133 1 2 14:12 ? 00:00:00 python /usr/bin/neucad start`
