#!/usr/bin/env python
# 
# Copyright (c) 2010 Renaissance Computing Institute. All rights reserved.
# 
# This software is released under GPLv2
# 
# Renaissance Computing Institute, 
# (A Joint Institute between the University of North Carolina at Chapel Hill,
# North Carolina State University, and Duke University)
# http://www.renci.org
# 
# For questions, comments please contact software@renci.org
# 
# This software simplifies post-boot configuration of a guest VM based on
# user data passed to an EC2/Eucalyptus instance. More information at
# http://geni-orca.renci.org
# 
# Author: Ilia Baldine (ibaldin@renci.org) 


import sys
import os
import tempfile

import boto.utils
import ConfigParser
import ipaddr
import platform

""" This script performs distribution-specific customization at boot-time
based on EC2 user-data passed to the instance """

class TempFile(file):
    def __init__(self, prefix='tmp', suffix=''):
        fd, path = tempfile.mkstemp(suffix, prefix)
        os.close(fd)
        self.path = path
        self.pid = os.getpid()
        file.__init__(self, path, "w")

        def __del__(self):
            if self.pid == os.getpid():
                os.remove(self.path)


class NEucaUserData(object):
    def __init__(self):
        self.userData=boto.utils.get_instance_userdata()
        fh = TempFile(prefix='euca-n-userdata')
        fh.write(self.userData)
        fh.close()
        
        self.config = ConfigParser.RawConfigParser()
        self.config.read(fh.path)
        
    def get(self, section, field):
	try:
            return self.config.get(section, field)
        except ConfigParser.NoOptionError:
            return 
        except ConfigParser.NoSectionError:
            return
 
    def getIfIp(self, ifName):
        ifString = self.get('interfaces', ifName);
        if not ifString:
            return 
        elem = ifString.split(':')
        if elem[0] == 'vlan' and len(elem) == 4:
            return ipaddr.IPv4Network(elem[3])
        if elem[0] == 'phys' and len(elem) == 3:
            return ipaddr.IPv4Network(elem[2])
        
    def getCustomScript(self):
        return self.config.get('instanceConfig', 'script')

    def empty(self):
        return len(self.userData) == 0

    def getAllUserData(self):
	return boto.utils.get_instance_userdata()
        
class NEucaOSCustomizer(object):
    """Generic OS customizer """
    def __init__(self, distro):
        self.userData = NEucaUserData()
        if self.userData.empty():
            print  >> sys.stderr, "Unable to retrieve NEuca user data, exiting"
            sys.exit(2)
        
    def customizeNetworking(self):
        pass
    
    def runCustomScript(self):
        pass

    def getAllUserData(self):
	return self.userData.getAllUserData()

    def getUserScript(self):
        return self.userData.get('instanceConfig', 'script')
    
class NEucaDebianCustomizer(NEucaOSCustomizer):
    """Debian/Ubuntu customizer """
    networkConfigurationFile = '/etc/network/interfaces'
    
    def __init__(self, distro):
        super(NEucaDebianCustomizer, self).__init__(distro)
        
    def __interfaceInConfig(self, intf):
        fh = open(self.networkConfigurationFile, 'r')
        for line in fh:
            if intf in line:
                return True
        return False
            
    def customizeNetworking(self):
        """Customize the /etc/network/interfaces: 
        append new interface definitions to it """
        super(NEucaDebianCustomizer, self).customizeNetworking()

        print >> sys.stderr, "NEuca performing Debian networking configuration"
        fh = open(self.networkConfigurationFile, 'a')
        i = 1
        while(True):
            ifName = 'eth%d'% i
            if not self.userData.getIfIp(ifName):
                break
            # check if it isn't already in the file
            if self.__interfaceInConfig(ifName):
		i = i + 1
                continue
            # append to file
            fh = open(self.networkConfigurationFile, 'a')
            fh.write('\n# NEuca-generated interface\n')
            fh.write('auto ' + ifName + '\n')
            fh.write('iface ' + ifName + ' inet static\n')
            fh.write('address ' + self.userData.getIfIp(ifName).ip.__str__() + '\n')
            fh.write('netmask ' + self.userData.getIfIp(ifName).netmask.__str__() + '\n')
            fh.close()
            i = i + 1
        

class NEucaRedhatCustomizer(NEucaOSCustomizer):
    networkConfigurationStub="/etc/sysconfig/network-scripts/ifcfg-"
    
    def __init__(self, distro):
        super(NEucaRedhatCustomizer, self).__init__(distro)
        
    def __checkIfFile(self, ifName):
        try:
            open(self.networkConfigurationStub + ifName, 'r')
        except:
            return False
        return True

    def customizeNetworking(self):
        """Customize the /etc/sysconfig/network-scripts/ifcfg-ethX
        files from user data"""
        super(NEucaRedhatCustomizer, self).customizeNetworking()

        print >> sys.stderr, "NEuca performing RedHat networking configuration"
        i = 1
        while(True):
            ifName = 'eth%d' % i
            if not self.userData.getIfIp(ifName):
                break
            # check if this file exists
            if self.__checkIfFile(ifName):
                i = i + 1
                continue
            fh = open(self.networkConfigurationStub + ifName, 'w')

            fh.write('# NEuca configured interface\n')
            fh.write('DEVICE=' + ifName + '\n')
            fh.write('BOOTPROTO=static\n')
            fh.write('ONBOOT=yes\n')
            fh.write('NETWORK=' + self.userData.getIfIp(ifName).network.__str__() + '\n')
            fh.write('NETMASK=' + self.userData.getIfIp(ifName).netmask.__str__() + '\n')
            fh.write('BROADCAST=' + self.userData.getIfIp(ifName).broadcast.__str__() + '\n')
            fh.write('IPADDR=' + self.userData.getIfIp(ifName).ip.__str__() + '\n')
            fh.close()
            i = i + 1
            
def main():
    
    distro = platform.dist()[0]

    head,invokeName = os.path.split(sys.argv[0])

    if invokeName == "neuca":
	print "Invoke as"
	print "\tneuca-netconf - to configure host networking"
	print "\tneuca-user-script - to retrieve user-specified post-boot script"
        print "\tneuca-user-data - to retrieve full user data"
        print "\tneuca-distro - to check distribution detection"
        sys.exit(0)

    if invokeName == "neuca-distro":
        print distro
        sys.exit(0)

    # choose which OS
    customizer = { 
        "debian": NEucaDebianCustomizer,
        "Ubuntu": NEucaDebianCustomizer,
        "redhat": NEucaRedhatCustomizer,
        "fedora": NEucaRedhatCustomizer,
    }.get(distro, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(distro)

    if invokeName == "neuca-netconf":
        customizer.customizeNetworking()

    if invokeName == "neuca-user-script":
        userScript = customizer.getUserScript()
        if userScript:
	    print customizer.getUserScript()

    if invokeName == "neuca-user-data":
	print customizer.getAllUserData()
	
    sys.exit(0)

if __name__ == "__main__":
    main()
    
