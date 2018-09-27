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

[comet_chameleon.yaml](https://github.com/RENCI-NRIG/neuca-guest-tools/blob/br217/comet_chameleon.yaml)

## Creating COMET context for chameleon node
Use [Python Comet Client](https://github.com/RENCI-NRIG/COMET-Client/tree/master/python-client ) to create COMET context.
### Create pubkeys context with value
`{"val_":"[{\"publicKey\":\"\"}]"}`

### Create etchost context with value
`{"val_":"[{\"hostName\":\"kthare10.novalocal\",\"ip\":\"\"}]"}`
NOTE: Replace kthare10.novalocal with hostname of Chameleon instance

### Example Commands
#### Hosts Context
`python3 comet_client.py -o create_family -c https://13.59.255.221:8111 -i ./input2.json`

#### PubKeys Context
`python3 comet_client.py -o create_family -c https://13.59.255.221:8111 -i ./input1.json`

# Usage on exogeni nodes
## Fetch neuca-guest-tools code by following commands
```
git clone https://github.com/RENCI-NRIG/neuca-guest-tools
cd neuca-guest-tools/neuca-py/
git checkout br217
```
NOTE: Until code is merged to master, following command is needed to get the latest neuca tools

## Install and Start neuca-guest-tools
```
python setup.py install
python /usr/bin/neucad restart
```

## Verify neuca daemon is running
```
ps -eaf | grep neuca
root 11133 1 2 14:12 ? 00:00:00 python /usr/bin/neucad start
```
