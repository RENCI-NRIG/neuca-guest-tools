#!/usr/bin/env python
# 
# Copyright (c) 2010 Renaissance Computing Institute except where noted. All rights reserved.
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
# Author: Paul Ruth (pruth@renci.org)

import sys
import os
import tempfile
import stat
import logging as LOG
import logging.handlers


import boto.utils
import ConfigParser
import ipaddr
import platform

from netaddr import *

""" This script performs distribution-specific customization at boot-time
based on EC2 user-data passed to the instance """


#Temp function so I don't have to run it on a real VM
def get_local_userdata():
    f = open('new_userdata.ini','r')
    rtnStr = f.read()
    f.close()
    
    return rtnStr
    

class TempFile(file):
    """Copyright (c) 2010 Alon Swartz <alon@turnkeylinux.org> - all rights reserved"""
    def __init__(self, prefix='tmp', suffix=''):
        fd, path = tempfile.mkstemp(suffix, prefix)
        os.close(fd)
        self.path = path
        self.pid = os.getpid()
        file.__init__(self, path, "w")

        def __del__(self):
            if self.pid == os.getpid():
                os.remove(self.path)

class NeucaScript:
    def __init__(self, name, script):
        LOG.debug('Createing NeucaScript: ' + name + "--" + script)

        self.scriptDir = '/var/run/neuca'
        self.name = name

        #os.makedirs('/var/run/neuca')
        if not os.path.exists(self.scriptDir):
            os.makedirs(self.scriptDir)
            
        if not os.path.exists(self.scriptDir + "/" + self.name):

            fd = open(self.scriptDir + "/" + self.name, 'w')
            fd.write(script)
            fd.close()
        
            os.chmod(self.scriptDir + "/" + self.name, stat.S_IXUSR)

            self.run()

        
    def run(self):
        executable = self.scriptDir + '/' + self.name
        if os.path.exists(executable):
            try:
                cmd = '%s 2>/dev/null' % (executable)
                LOG.info("Running: " + str(cmd))
                pipe = os.popen(cmd)
            except IOError:
                pass

    


class NEucaUserData(object):
    def __init__(self):
        # TODO:  change back for real VM 
        self.userData=boto.utils.get_instance_userdata()
        #self.userData=get_local_userdata()
        
        fh = TempFile(prefix='euca-n-userdata')
        fh.write(self.userData)
        fh.close()
        
        self.config = ConfigParser.RawConfigParser()
        self.config.read(fh.path)

    def updateUserData(self):
        
        # TODO:  change back for real VM 
        self.userData=boto.utils.get_instance_userdata() 
        #self.userData=get_local_userdata()

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
 
    def getBootScript(self):
        return self.config.get('scripts', 'bootscript')

    def getAllScripts(self):
        return self.config.items('scripts')

    def getInterface(self, iface):
        return self.config.get('interfaces',iface)

    def getAllInterfaces(self):
        return self.config.items('interfaces')

    def getAllScripts(self):
        return self.config.items('scripts')

    def getAllRoutes(self):
        return self.config.items('routes')

    def isRouter(self):
        try:
            isRtr = self.config.get('global','router').lower()
            if isRtr == 'true':
                isRtr = True
            else:
                isRtr = False
        except:
            isRtr = False
            
        return isRtr
        

    def empty(self):
        return len(self.userData) == 0

    def getAllUserData(self):
	return self.userData 
    
class NEucaOSCustomizer(object):
    """Generic OS customizer """
    def __init__(self, distro):
        self.userData = NEucaUserData()
        if self.userData.empty():
            LOG.error("Unable to retrieve NEuca user data, exiting")
            sys.exit(2)
        
    def updateNetworking(self):
        pass

    def customizeNetworking(self):
        pass
    
    def runCustomScript(self):
        pass

    def getBootScript(self):
        return self.userData.getBootScript()  

    def getAllScripts(self):
        return self.userData.getAllScripts()  

    
    def isRouter(self):
        return self.userData.isRouter()

    def getAllRoutes(self):
        return self.userData.getAllRoutes()

class NEucaDebianCustomizer(NEucaOSCustomizer):
    """Debian/Ubuntu customizer """
    networkConfigurationFile = '/etc/network/interfaces'
    
    def __init__(self, distro):
        super(NEucaDebianCustomizer, self).__init__(distro)
        

    def initLogging(self):
        
        LOG.basicConfig(level=LOG.DEBUG, filename='/dev/null')
        
        if not os.path.exists('/var/log/neuca'):
            os.makedirs('/var/log/neuca')

        handler = LOG.handlers.RotatingFileHandler("/var/log/neuca/neuca-agent.log", backupCount=50, maxBytes=5000000)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        LOG.getLogger('').addHandler(handler)
        
        LOG.info('Starting Logger')
	

    def __interfaceInConfig(self, intf):
        fh = open(self.networkConfigurationFile, 'r')
        for line in fh:
            if intf in line:
                return True
        return False
    
    def __findIfaceByMac(self, mac):
        """ 
        Gets the interface name for a given mac address

        based on code from uuid.py by Ka-Ping Yee <ping@zesty.ca> 
        """

        import os
        args = '-a'
        hw_identifiers = ['hwaddr', 'ether', 'HWaddr']
        command = 'ifconfig'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                cmd = '%s %s 2>/dev/null' % (executable, args)
                pipe = os.popen(cmd)
            except IOError:
                continue
            
            for line in pipe:
                #if it doesn't begin with white space we have a new iface
                words = line.lower().split() 
                if not line.startswith((' ','\t','\n')) and len(words) > 0:
                    iface = words[0].strip(':')
                
                for i in range(len(words)):
                    if words[i] in hw_identifiers and words[i+1].replace(':','') == mac:
                        return iface
        return None
              
    def __ifaceDown(self, iface):
        import os
        args = ''
        command = 'ifconfig'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                cmd = '%s %s %s down 2>/dev/null' % (executable, args, iface)
                LOG.info("iface down: " + str(cmd))
                pipe = os.popen(cmd)
            except IOError:
                continue


    def __ifaceUp(self, iface, ip):
        import os
        args = ''
        command = 'ifconfig'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                cmd = '%s %s %s %s up 2>/dev/null' % (executable, args, iface, ip)
                pipe = os.popen(cmd)
            except IOError:
                continue

    def __updateInterface(self, mac, ip, state):
        #print mac + " " + str(ip) + " " + state
        #find iface by mac
        iface = self.__findIfaceByMac(mac)
        #print iface

        #config iface
        if state == 'down':
            self.__ifaceDown(iface)
            pass
        elif state == 'up':
            self.__ifaceUp(iface,ip)
            pass
        elif state == 'user':
            #ignore because user is in control
            pass
        else:
            #unkown state
            LOG.error("NEuca found unkown interface state: " + str(mac) + " " + str(state))

    def __updateRouter(self, isRtr):
        f = open('/proc/sys/net/ipv4/ip_forward','w')
        if isRtr:
            LOG.info("Router Yes")
            f.write('1')
        else:
            LOG.info("Router No")
            f.write('0')
        f.close()
            

    def __addRoute(self,network, router):
        import os
        args = ''
        command = 'ip'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                cmd = '%s %s route add  %s via %s 2>/dev/null' % (executable, args, network, router)
                LOG.info("Add route: " + str(cmd))
                pipe = os.popen(cmd)
            except IOError:
                continue


    def __delRoute(self, network):
        import os
        args = ''
        command = 'ip'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                LOG.info("Deleting route:  " +  '%s %s del %s 2>/dev/null' % (executable, args, network))
                cmd = '%s %s route del %s 2>/dev/null' % (executable, args, network)
                pipe = os.popen(cmd)
            except IOError:
                continue

    def __updateRoute(self, network, router):
        try:
            IPNetwork(network)
        except:
            LOG.error("NEuca: network not in cidr (" + str(network) + ")")

        if router == 'down':
            LOG.info('route down: ' + str(network) + " " + str(router))
            self.__delRoute(network)
        elif router == 'user':
            pass
        else:
            try:
                IPAddress(router)
            except:
                LOG.error("NEuca: router not in valid format ("+ str(router) + "), or invalid state.")
                return
            LOG.info('route up: ' + str(network) + " " + str(router))
            self.__delRoute(network)
            self.__addRoute(network,router)

          

    def updateNetworking(self):
        """
        Add/remove newtork interfaces using ifconfig, etc. 
        """
        super(NEucaDebianCustomizer, self).updateNetworking()

        #update interfaces
        interfaces = self.userData.getAllInterfaces()
        for iface in interfaces:
            mac = iface[0]
            state = iface[1].split(':')[0]
            try:
                ip_type = iface[1].split(':')[1]
                ip = iface[1].split(':')[2]
            except:
                ip_type = None
                ip = None
            self.__updateInterface(mac,ip,state)

        #update routes
        self.__updateRouter(self.isRouter())
        routes = self.getAllRoutes()
        for route in routes:
            self.__updateRoute(route[0],route[1])
    
    def runNewScripts(self):
        import time
        self.userData.updateUserData()

        for i in  self.getAllScripts():
            script = NeucaScript(i[0],i[1])
        
            
        
    def getAllUserData(self):
        return self.userData.getAllUserData()

class NEucaRedhatCustomizer(NEucaOSCustomizer):
    networkConfigurationFile="/etc/sysconfig/network"
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

        
	# turn off zeroconf so 169.254.x.x/16 route doesn't move
	# blocking access to cloud
	fh = open(self.networkConfigurationFile, 'a')
	fh.write('NOZEROCONF=yes\n')
	fh.close()
	# create interface definitions
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
        

import time
from daemon import runner

class NEucad():
    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path =  '/var/run/neucad.pid'
        self.pidfile_timeout = 5
        
        self.distro = platform.dist()[0]

    def run(self):
        import time


        # choose which OS
        self.customizer = {
            "debian": NEucaDebianCustomizer,
            "Ubuntu": NEucaDebianCustomizer,
            "redhat": NEucaRedhatCustomizer,
            "fedora": NEucaRedhatCustomizer,
            "centos": NEucaRedhatCustomizer,
        }.get(self.distro, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(self.distro)


        self.customizer.initLogging()

        while True:
            try:
                LOG.debug("Polling")
                self.customizer.updateNetworking()
                self.customizer.runNewScripts()
                time.sleep(10)
	    except KeyboardInterrupt:
                LOG.error("Exception: KeyboardInterrupt")
		sys.exit(0)
	    except Exception as e:
		LOG.error("Exception in loop: " + str(type(e)))

        

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
	"centos": NEucaRedhatCustomizer,
    }.get(distro, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(distro)

    if invokeName == "neuca-netconf":
        #customizer.customizeNetworking()
        customizer.updateNetworking()
        
    if invokeName == "neuca-user-script":
        userScript = customizer.getBootScript()
        if userScript:
	    print userScript 

    if invokeName == "neuca-all-user-scripts":
        userScripts = customizer.getAllScripts()
        for script in userScripts:
            print script
        
    if invokeName == "neuca-user-data":
	print customizer.getAllUserData()
	

    if invokeName == "neuca-routes":
        print "Router: " + str(customizer.isRouter())
        print customizer.getAllRoutes()


    if invokeName == "neuca-run-scripts":
        print customizer.runNewScripts()


    if invokeName == "neucad":
        app = NEucad()
        daemon_runner = runner.DaemonRunner(app)
        daemon_runner.do_action()



    sys.exit(0)

if __name__ == "__main__":
    main()
    
