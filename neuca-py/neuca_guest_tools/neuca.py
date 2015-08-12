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
import subprocess
import string

import boto.utils
import ConfigParser
import ipaddr
import traceback
import re
import socket
import time

import abc

import neuca_guest_tools as neuca

import logging, logging.handlers

from netaddr import *
from subprocess import *

from os import kill
from signal import alarm, signal, SIGALRM, SIGKILL
from subprocess import PIPE, Popen
from optparse import OptionParser
from daemon import runner
from lockfile import LockTimeout

""" This script performs distribution-specific customization at boot-time
based on EC2 user-data passed to the instance """

CONFIG = ConfigParser.SafeConfigParser()
CONFIG.add_section('runtime')
CONFIG.add_section('logging')
CONFIG.set('runtime', 'set-loopback-hostname', neuca.__SetLoopbackHostname__)
CONFIG.set('runtime', 'loopback-address', neuca.__LoopbackAddress__)
CONFIG.set('runtime', 'dataplane-macs-to-ignore', '')
CONFIG.set('runtime', 'state-directory', neuca.__StateDir__)
CONFIG.set('runtime', 'pid-directory', neuca.__PidDir__)
CONFIG.set('runtime', 'pid-file', neuca.__PidFile__)
CONFIG.set('logging', 'log-directory', neuca.__LogDir__)
CONFIG.set('logging', 'log-file', neuca.__LogFile__)
CONFIG.set('logging', 'log-level', neuca.__LogLevel__)
CONFIG.set('logging', 'log-retain', neuca.__LogRetain__)
CONFIG.set('logging', 'log-file-size', neuca.__LogFileSize__)

LOGGER = 'neuca_guest_tools_logger'
IPV4_LOOPBACK_NET = '127.0.0.0/8'

# Temp function so I don't have to run it on a real VM
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


class Commands:
    @classmethod
    def run_cmd(self, args):
        cmd = args
        log = logging.getLogger(LOGGER)
        log.debug("running command: " + " ".join(cmd))
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        retval = p.communicate()[0]
                
        return retval

    @classmethod
    def run(self, args, cwd = None, shell = False, kill_tree = True, timeout = -1, env = None):
        '''
        Run a command with a timeout after which it will be forcibly
        killed.

        Mostly from Alex Martelli solution (probably from one of his 
        python books) posted on stackoverflow.com
        '''
        class Alarm(Exception):
            pass

        def alarm_handler(signum, frame):
            raise Alarm

        log = logging.getLogger(LOGGER)
        log.debug("run: args= " + str(args))
        #p = Popen(args, shell = shell, cwd = cwd, stdout = PIPE, stderr = PIPE, env = env)
        p = Popen(args, stdout=PIPE, stderr=STDOUT)
        if timeout != -1:
            signal(SIGALRM, alarm_handler)
            alarm(timeout)
        try:
            stdout, stderr = p.communicate()
            if timeout != -1:
                alarm(0)
        except Alarm:
            pids = [p.pid]
            if kill_tree:
                pids.extend(self._get_process_children(p.pid))
            for pid in pids:
                # process might have died before getting to this line
                # so wrap to avoid OSError: no such process
                try: 
                    kill(pid, SIGKILL)
                except OSError:
                    pass
            return -9, '', ''
        return p.returncode, stdout, stderr

    @classmethod
    def _get_process_children(self, pid):
        p = Popen('ps --no-headers -o pid --ppid %d' % pid, shell = True,
                  stdout = PIPE, stderr = PIPE)
        stdout, stderr = p.communicate()
        return [int(p) for p in stdout.split()]

    @classmethod
    def source(self, script, update=1):
        pipe = Popen(". %s; env" % script, stdout=PIPE, shell=True, env={'PATH': os.environ['PATH']})
        data = pipe.communicate()[0]
        env = dict((line.split("=", 1) for line in data.splitlines()))
        if update:
           os.environ.update(env)
        return env


class NeucaScript:
    def __init__(self, name, script):
        self.log = logging.getLogger(LOGGER)
        self.log.debug('Creating NeucaScript: ' + name + "--" + script)

        self.scriptDir = CONFIG.get('runtime', 'state-directory')
        self.name = name

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
                #cmd = '%s 2>/dev/null' % (executable)
                cmd = str(executable)
                self.log.info("Running: " + str(cmd))
                #pipe = os.popen(cmd)
                subprocess.Popen(["nohup", cmd])
            except IOError:
                pass

#abstract class for data 
class NEucaData(object):
    __metaclass__ = abc.ABCMeta

    @classmethod
    def create(self):
        #get cred paths and ids from userdata file
        userData = NEucaUserData()
        userData.update()

        data_source = userData.get("global","neuca_data_source")
        
        print "data_source: " + str(data_source)
        
        if data_source == "userdata":
            return userData
        elif data_source == "comet":
            return NEucaCometData(userData)
        else:
            return userData

    @abc.abstractmethod
    def update(self):
        return

    @abc.abstractmethod
    def get(self, section, field):
        return

    @abc.abstractmethod
    def getBootScript(self):
        return
    
    @abc.abstractmethod
    def getAllScripts(self):
        return

    @abc.abstractmethod
    def getInterface(self, iface):
        return

    @abc.abstractmethod
    def getAllInterfaces(self):
        return

    @abc.abstractmethod
    def getAllStorage(self):
        return

    @abc.abstractmethod
    def getAllScripts(self):
        return

    @abc.abstractmethod
    def getAllRoutes(self):
        return

    @abc.abstractmethod
    def isRouter(self):
        return

    @abc.abstractmethod
    def getISCSI_iqn(self):
        return

    @abc.abstractmethod
    def getHostname(self):
        return

    @abc.abstractmethod
    def empty(self):
        return
    

class NEucaCometData(NEucaData):
    def __init__(self, userdata):
        self.__data=None
        
        self.log = logging.getLogger(LOGGER)

        #get cred paths and ids from userdata file
        #self.userData = NEucaUserData()
        self.userData = userdata
        self.userData.update()
        
        self.sliceID = self.userData.get("global","slice_id")
        self.reservationID = self.userData.get("global","reservation_id")
        self.comet_vm_properties_path = self.userData.get("global","comet_vm_properties")
        self.comet_vm_keystore_path = self.userData.get("global","comet_vm_keystore")
        self.comet_vm_truststore_path = self.userData.get("global","comet_vm_truststore")

        #decode creds from base64
        #self.log.info("self.sliceID: " + str(self.sliceID))
        #self.log.info("self.reservationID: " + str(self.reservationID))
        #self.log.info("self.comet_vm_properties: " + str(self.comet_vm_properties_path))
        #self.log.info("self.comet_vm_keystore: " + str(self.comet_vm_keystore_path))
        #self.log.info("self.comet_vm_truststore: " + str(self.comet_vm_truststore_path))

        print "self.sliceID: " + str(self.sliceID)
        print "self.reservationID: " + str(self.reservationID)
        print "self.comet_vm_properties: " + str(self.comet_vm_properties_path)
        print "self.comet_vm_keystore: " + str(self.comet_vm_keystore_path)
        print "self.comet_vm_truststore: " + str(self.comet_vm_truststore_path)
        
        #decode the keystores from base64
        self.__decode_keystores()

    def __decode_keystores(self):
        keystore64_path = self.comet_vm_keystore_path
        truststore64_path = self.comet_vm_truststore_path
        
        keystore_path = re.sub(r"/.base64$", "", keystore64_path)
        truststore_path = re.sub(r"/.base64$", "", truststore64_path)

        print "keystore64_path: " + keystore64_path
        print "keystore_path  : " + keystore_path

        print "truststore64_path: " + truststore64_path
        print "truststore_path  : " + truststore_path

        

        with open (keystore64_path, "r") as keystore64_file:
            with open (keystore_path, "wb") as keystore_file:
                keystore_file.write(base64.decode(keystore64_file.read()))
                
        with open (truststore64_path, "r") as truststore64_file:
            with open (truststore_path, "wb") as truststore_file:
                truststore_file.write(base64.decode(truststore64_file.read()))
    
        self.comet_vm_keystore_path = keystore_path
        self.comet_vm_truststore_path = truststore_path


    def __query_comet(self):
        cmd = 'java'
        exeExists=False
        for dir in ['', '/bin/', '/usr/bin', '/sbin', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            #self.log.error('java does not exist in paths ., /bin, or /usr/bin')`
            return None


        comet_jar="/root/comet.jar"

        #java -jar comet.jar -configFile comet.vm.properties -getHostname aee48bcc-a7de-45e3-8318-373c23c5b12e 5317514e-9746-485a-affe-0d706f382adf
        try:
            cmd = [ str(executable), "-jar", comet_jar, "-configFile", self.comet_vm_properties_path , "-getHostname" , self.sliceID , self.reservationID ]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                print 'rtncode: ' + str(rtncode) + 'Failed to start open-iscsi with command: ' + str(cmd)
                #self.log.error('rtncode: ' + str(rtncode) + 'Failed to start open-iscsi with command: ' + str(cmd))
                return None
        except Exception as e:
            print 'Exception: Failed to query comet with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc())
            #self.log.error('Exception: Failed to query comet with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return

        print "cmd: " + str(cmd)
        print "rtncode: " + str(rtncode)
        print "data_stdout: " + str(data_stdout)
        print "data_stderr: " + str(data_stderr)

        

        return
        

    def update(self):
        return

    def get(self, section, field):
        return None

    def getBootScript(self):
        return None

    def getAllScripts(self):
        return None

    def getInterface(self, iface):
        return None

    def getAllInterfaces(self):
        return None

    def getAllStorage(self):
        return None

    def getAllScripts(self):
        return None

    def getAllRoutes(self):
        return None

    def isRouter(self):
        return None

    def getISCSI_iqn(self):
        return None

    def getHostname(self):
        command = 'java'
        exeExists=False
        for dir in ['', '/bin/', '/usr/bin', '/sbin', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

            if not exeExists:
                #self.log.error('java does not exist in paths ., /bin, or /usr/bin')`   
                return None


        comet_jar="/root/comet.jar"

        #java -jar comet.jar -configFile comet.vm.properties -getHostname aee48bcc-a7de-45e3-8318-373c23c5b12e 5317514e-9746-485a-affe-0d706f382adf   
        try:
            cmd = [ str(executable), "-jar", comet_jar, "-configFile", self.comet_vm_properties_path , "-getHostname" , self.sliceID , self.reservationID ]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                print 'rtncode: ' + str(rtncode) + 'Failed to start open-iscsi with command: ' + str(cmd)
                #self.log.error('rtncode: ' + str(rtncode) + 'Failed to start open-iscsi with command: ' + str(cmd)) 
                return None

        except Exception as e:
            print 'Exception: Failed to query comet with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc())
            #self.log.error('Exception: Failed to query comet with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))  
            return

        print "cmd: " + str(cmd)
        print "rtncode: " + str(rtncode)
        print "data_stdout: " + str(data_stdout)
        print "data_stderr: " + str(data_stderr)

        return 

    def empty(self):
        return None

    def getAllUserData(self):
        return None
        return "NEucaCometData.getAllUserData NOT IMPLEMENTED"



class NEucaUserData(NEucaData):
    def __init__(self):
	self.userData=None

    def update(self):
        # TODO:  change back for real VM 
        self.userData=boto.utils.get_instance_userdata() 
        #self.userData=get_local_userdata()

        fh = TempFile(prefix='neuca-userdata')
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
        try:
            bootscript = self.config.get('scripts', 'bootscript')
        except:
            bootscript = None

        return bootscript

    def getAllScripts(self):
        return self.config.items('scripts')

    def getInterface(self, iface):
        return self.config.get('interfaces',iface)

    def getAllInterfaces(self):
        return self.config.items('interfaces')

    def getAllStorage(self):
        return self.config.items('storage')

    def getAllScripts(self):
        return self.config.items('scripts')

    def getAllRoutes(self):
        return self.config.items('routes')

    def isRouter(self):
        try:
            isRtr = self.config.get('global','router').lower()
        except:
            isRtr = 'user'
            
        return isRtr
        
    def getISCSI_iqn(self):
        try:
            iqn = self.config.get('global','iscsi_initiator_iqn').strip()
        except:
            iqn = '#No iSCSI initiator in user data'

        return iqn

    def getHostname(self):
        return self.config.get('global','host_name').strip()
        
    def empty(self):
        return len(self.userData) == 0

    def getAllUserData(self):
	return self.userData 
    

class NEucaOSCustomizer(object):
    """Generic OS customizer """
    def __init__(self, distro):
        #self.userData = NEucaUserData()
        self.userData = NEucaData.create()
        self.log = logging.getLogger(LOGGER)
        self.ignoredMacSet = set()

        #if self.userData.empty():
        #    self.log.warning("Unable to retrieve NEuca user data")
	pass        

    def updateNetworking(self):
        pass
    
    def updateStorage(self):
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

    def getISCSI_iqn(self):
        return self.userData.getISCSI_iqn()

    def getAllRoutes(self):
        return self.userData.getAllRoutes()

    def getUserData(self):
        return self.userData

    def getPublicIP(self):
	return str(boto.utils.get_instance_metadata()['public-ipv4'])


class NEucaLinuxCustomizer(NEucaOSCustomizer):
    """Linux customizer """

    def __init__(self, distro, iscsiInitScript):
        super(NEucaLinuxCustomizer, self).__init__(distro)        
        self.iscsiInitScript = iscsiInitScript
        self.storage_dir = neuca.__StorageDir__
        self.hostsFile = '/etc/hosts'

    def __findIfaceByMac(self, mac):
        """ 
        Gets the interface name for a given mac address

        based on code from uuid.py by Ka-Ping Yee <ping@zesty.ca> 
        """

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
                if not line.startswith((' ', '\t', '\n')) and len(words) > 0:
                    iface = words[0].strip(':')
                
                for i in range(len(words)):
                    if words[i] in hw_identifiers and words[i+1].replace(':', '') == mac:
                        return iface
        return None

    def __macDisabledByUser(self, mac):
        mac_cleaned = mac.lower().replace(':', '')
        return (mac_cleaned in self.ignoredMacSet)
 
    def __ifaceDown(self, iface):
        args = ''
        command = 'ifconfig'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                cmd = '%s %s %s down 2>/dev/null' % (executable, args, iface)
                self.log.info("iface down: " + str(cmd))
                pipe = os.popen(cmd)
            except IOError:
                continue

    def __ifaceUp(self, iface, ip):
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

        if (iface == None):
            self.log.warning("Could not find interface having MAC address " + str(mac) + " at this time.")
            return    

        if (self.__macDisabledByUser(mac)):
            self.log.info("Interface " + iface + " having MAC address " + str(mac) + " is being ignored at user request.")
            return

        #config iface
        if state == 'down':
            self.__ifaceDown(iface)
            pass
        elif state == 'up':
            self.__ifaceUp(iface, ip)
            pass
        elif state == 'user':
            #ignore because user is in control
            pass
        else:
            #unknown state
            self.log.error("NEuca found unknown interface state: " + str(mac) + " " + str(state))

    def __checkISCSI_shouldFormat(self, device, fs_type):
        self.log.debug('__updateISCSI_shouldFormat(self, ' + device + ', ' + fs_type + ')')
        current_fs_type=None
        command = 'blkid'
        exeExists=False
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            self.log.error('blkid executable does not exist in paths ., /sbin, or /usr/sbin.' +
                      'Cannot check for existing fs_type. Will not format disk')
            return False

        try:
            cmd = [ str(executable), str(device) ]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)

            if rtncode == 2:
                #disk unformated
                self.log.debug('shouldFormat -> True, disk is unformatted: ' + str(device))
                return True

            if rtncode != 0:
                self.log.error('rtncode: ' + str(rtncode) + 'Failed to test for device filesystem (' +
                          str(device) + ' with command: ' + str(cmd))
                self.log.error('Cannot check for existing fs_type.  Will not format disk')
                return False

            for v in data_stdout.split(' '):
                if v.split('=')[0] != 'TYPE':
                    continue

                if len(v.split('=')) > 1 and v.split('=')[0] == 'TYPE':
                    current_fs_type = v.split('=')[1]
                    if current_fs_type  == '"' + fs_type + '"':
                       #found match
                        self.log.debug('shouldFormat -> False, disk is formatted with desired fs_type: ' +
                                  str(device) + ', ' + str(fs_type))
                        return False
                break
        except Exception as e:
            self.log.error('Exception: Failed to test for device filesystem. ' +
                      'Cannot check for existing fs_type. Will not format disk (' + str(device) +
                      ') with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" +
                      str(traceback.format_exc()))

        self.log.debug('shouldFormat -> True, disk is formatted with ' + str(current_fs_type) + ': ' +
                  str(device) + ', ' + str(fs_type))
        return True

    def __checkISCSI_handled(self, device_entry):
        if os.path.exists(str(self.storage_dir) + '/' + str(device_entry)):
            return True
        else:
            return False

    def __updateISCSI_initiator(self, new_initiator_iqn):
        #test existing iscsi iqn, if same then skip /etc/iscsi/initiatorname.iscsi
        f = open('/etc/iscsi/initiatorname.iscsi','r')
        initiatorname_iscsi = f.read()
        f.close()

        found = False
        lines = initiatorname_iscsi.split('\n')
        for line in lines:
            if line.strip().startswith('InitiatorName'):
                tokens = line.split('=')
                if len(tokens) >= 2 and tokens[0].strip() == 'InitiatorName':
                    if tokens[1].strip() == str(new_initiator_iqn).strip():
                        self.log.warning("__updateISCSI_initiator: new and old iqn are the same (" +
                                         str(new_initiator_iqn) +  "), not updating.")
                        return
                    else:
                        index = lines.index(line)
                        self.log.debug('line: ' + str(line) +', lines[' + str(index) + ']: ' + str(lines[index]))
                        lines[index] = '##' + line
                        lines.insert(index+1,'InitiatorName=' + str(new_initiator_iqn) + '\n') 
                        found = True
                        break
        
        if not found:
            lines.append('InitiatorName=' + str(new_initiator_iqn) + '\n')

        self.log.debug('initiatorname (lines): ' + str(lines))
                          
        #stop open iscsi
        command = 'service'
        exeExists=False
        for dir in ['', '/sbin', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            self.log.error('Unable to find service utility to run ' + str(self.iscsiInitScript)  +  ' service.')
            return

        try:
            # Stop iSCSI

            cmd = [ str(executable), self.iscsiInitScript, "stop" ]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error('rtncode: ' + str(rtncode) + 'Failed to shutdown open-iscsi with command: ' + str(cmd))
                return None
        except Exception as e:
            self.log.error('Exception: Failed to shutdown open-iscsi with command: ' + str(cmd) + " " +
                      str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return

        #update initiator file
        f = open('/etc/iscsi/initiatorname.iscsi','w')
        for line in lines:
            f.write(str(line) + '\n')
        f.close()

        try:
            # Start iSCSI
            cmd = [ str(executable), self.iscsiInitScript, "start" ]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error('rtncode: ' + str(rtncode) + 'Failed to start open-iscsi with command: ' + str(cmd))
                return None
        except Exception as e:
            self.log.error('Exception: Failed to start open-iscsi with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return

        #clean up files from previous mounts, rm /var/run/neuca/storage/*
        for f in os.listdir(self.storage_dir):
            self.log.debug('Removing file: ' + str(f))
            os.remove(self.storage_dir + f)

    def __ISCSI_discover(self, ip, port):
        self.log.debug('__ISCSI_discover(self, ' + str(ip) + ')')
        command = 'iscsiadm'
        exeExists=False
        for dir in ['', '/bin/', '/usr/bin', '/sbin', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            self.log.error('iSCSI executable iscsiadm does not exist in paths ., /bin, or /usr/bin')
            return None

        try:
            #discover targets: iscsiadm --mode discovery --type sendtargets --portal 172.16.101.43
            cmd = [ str(executable), "--mode", "discovery", "--type", "sendtargets", "--portal", str(ip) ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error('rtncode: ' + str(rtncode) + 'Failed to discover iSCSI targets with command: ' + str(cmd))
                return None

            self.log.debug('Targets: ' + str(data_stdout))
        except Exception as e:
            self.log.error('Exception: Failed to discover iSCSI targets for device with command: ' +
                           str(cmd) + " " +
                           str(type(e)) + " : " +
                           str(e) + "\n" + str(traceback.format_exc()))
            return None

        targets = []
        lines = data_stdout.split('\n')
        for line in lines:
            if line.strip().startswith(str(ip)):
                line_split = line.split()
                self.log.debug('line_split: ' + str(line_split))
                if len(line_split) >= 2 and line_split[0].startswith(str(ip) + ':' + str(port)):
                    targets.append(line_split[1].strip())
                    self.log.debug('adding target: ' + str(line_split[1].strip()))

        self.log.debug('return targets: ' + str(targets))
        return targets

    def __updateISCSI_attach(self, device, target, ip, port, chap_user, chap_pass):
        self.log.debug('__updateISCSI_target_login(self, ' + str(device) + ', ' + str(target) +
                  ', ' + str(ip)  + ', ' + str(port) +')')
        command = 'iscsiadm'
        exeExists=False
        for dir in ['', '/bin/', '/usr/bin', '/sbin', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            self.log.error('iSCSI executable iscsiadm does not exist in paths ., /bin, or /usr/bin')
            return

        #Attach the device is it is not already attached
        if not os.path.exists(device):
            #iSCSI device not attached
            #set authmethod:
            #iscsiadm --mode node --targetname target0 --portal 172.16.101.43:3260 --op=update --name node.session.auth.authmethod --value=CHAP
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip) +
                        ":" + str(port), "--op=update", "--name", "node.session.auth.authmethod", "--value=CHAP" ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    self.log.error('rtncode: ' + str(rtncode) + 'Failed to set iSCSI authmethod device (' +
                              str(device) + ' with command: ' + str(cmd))
                    return
            except Exception as e:
                self.log.error('Exception: Failed to set iSCSI authmethod device  (' +
                          str(device) + ') with command: ' + str(cmd) + " " +
                          str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
                return

            #set chap username:
            #iscsiadm --mode node --targetname target0 --portal 172.16.101.43:3260 --op=update --name node.session.auth.username --value=username                                                                                                               
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip) +
                        ":" + str(port), "--op=update", "--name", "node.session.auth.username", "--value=" + str(chap_user) ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    self.log.error('rtncode: ' + str(rtncode) + 'Failed to set iSCSI chap user for device (' +
                              str(device) + ' with command: ' + str(cmd))
                    return
            except Exception as e:
                self.log.error('Exception: Failed to set iSCSI chap user for device  (' +
                          str(device) + ') with command: ' + str(cmd) + " " +
                          str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
                return

            #set chap password:
            #iscsiadm --mode node --targetname target0 --portal 172.16.101.43:3260 --op=update --name node.session.auth.password --value=password
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip) +
                        ":" + str(port), "--op=update", "--name", "node.session.auth.password", "--value="+str(chap_pass) ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    self.log.error('rtncode: ' + str(rtncode) + 'Failed to set iSCSI chap password device (' +
                              str(device) + ' with command: ' + str(cmd))
                    return
            except Exception as e:
                self.log.error('Exception: Failed to set iSCSI chap pass device  (' +
                          str(device) + ') with command: ' + str(cmd) + " " +
                          str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
                return

            #attach target:
            #iscsiadm --mode node --targetname target0 --portal 172.16.101.43:3260 --login
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip) +
                        ":" + str(port), '--login' ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    self.log.warning('rtncode: ' + str(rtncode) + 'Failed to attach iSCSI target for device (' +
                                str(device) + ' with command: ' + str(cmd))
                    self.__updateISCSI_target_rescan(device, target, ip, port)
                else:
                    self.log.debug('Attach stdout: ' +str(data_stdout))
            except Exception as e:
                self.log.error('Failed to connect iSCSI device (' + str(device) + ' with command: ' + str(cmd))
                self.__updateISCSI_target_rescan(device, target, ip, port)
        else:
            self.log.debug('Device already connected: ' + str(device))
            return

        self.log.debug('Checking device attached: ' + str(device))
        count = 0
        while not os.path.exists(device):
            self.log.debug('Device not attached: ' + str(device) + ', try ' + str(count))
            count = count + 1
            if count > 10:
                break
            time.sleep(1)

    def __updateISCSI_target_rescan(self, device, target, ip, port):
        self.log.debug('__updateISCSI_target_rescan(self, ' + str(device) +', ' + str(target)  + ')')
        command = 'iscsiadm'
        exeExists=False
        for dir in ['', '/bin/', '/usr/bin', '/sbin', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            self.log.error('iSCSI executable iscsiadm does not exist in paths ., /bin, or /usr/bin')
            return

        #iscsiadm -m discovery -t st -p 10.104.0.2 -o delete -o new
        try:
            cmd = [ str(executable), "-m", "discovery", "-t", "st", "--portal", str(ip) +
                    ":" + str(port), "-o", "delete", "-o", "new" ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error('rtncode: ' + str(rtncode) + 'Failed re-discovery with command: ' + str(cmd))
                return
        except Exception as e:
            self.log.error('Exception: Failed re-discovery with command: ' + str(cmd) + " " +
                      str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return
         
        #iscsiadm -m session --rescan          
        try:
            cmd = [ str(executable), "--mode", "session", "--rescan" ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error('rtncode: ' + str(rtncode) + 'Failed to rescan with command: ' + str(cmd))
                return
        except Exception as e:
            self.log.error('Exception: Failed to rescan with command: ' + str(cmd) + " " +
                      str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return

        self.log.debug('Checking device attached: ' + str(device))
        count = 0
        while not os.path.exists(device):
            self.log.debug('Device not attached: ' + str(device) + ', try ' + str(count))
            count = count + 1
            if count > 10:
                break
            time.sleep(1)
        

    def __updateISCSI_format(self, device, fs_type, fs_options):
        self.log.debug('__updateISCSI_format(self, '+device+', ' + fs_type  + ', ' + fs_options + ')')
        command = 'mkfs'
        exeExists=False
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            self.log.error('Executable mkfs does not exist in paths ., /sbin, or /usr/sbin')
            return
        
        if os.path.exists(device):
            try:
              
                cmd = [ str(executable), "-t", fs_type ]
                for option in re.split('\s+', fs_options):  
                    cmd.append(str(option))
                cmd.append(str(device))

                self.log.info('Formatting iSCSI device ' + str(device) + ' with command: ' + str(cmd))

                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=3600)
                if rtncode != 0:
                    self.log.error('rtncode: ' + str(rtncode) + ', Failed to format iSCSI targets for device (' +
                              str(device) + ' with command: ' + str(cmd))
                    self.log.error('stdout: ' + str(data_stdout))
                    self.log.error('stderr: ' + str(data_stderr))
                    return
            except Exception as e:
                self.log.error('Exception: Failed to format iSCSI targets for device (' + str(device) +
                          ') with command: ' + str(cmd) + " " + str(type(e)) + " : " + str(e) + "\n" +
                          str(traceback.format_exc()))
        else:
            self.log.debug('iSCSI device not attached: ' + str(device))

    def __updateISCSI_mount(self, device, fs_type, mount_point):
        self.log.debug('__updateISCSI_mount(self, '+device+', ' + fs_type + ', ' + mount_point  + ')')
        command = 'mount'
        exeExists=False
        for dir in ['', '/bin/', '/usr/bin', '/sbin', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            self.log.error('Executable mount does not exist in paths ., /bin, or /usr/bin')
            return
        
        #Mount the file system
        if not os.path.exists(device):
            self.log.debug('Failed to mount device because iSCSI device not attached: ' + str(device))
            return

        self.log.debug('Checking dir: ' + str(mount_point))
        try:
            os.makedirs(str(mount_point))
            self.log.debug('Created ' + str(mount_point))
        except OSError as exception:
            self.log.debug('Mount point exists: ' + str(mount_point))


        try:
            cmd = [ str(executable), "-t", str(fs_type), str(device), str(mount_point)]
   
            self.log.info('Mounting iSCSI device ' + str(device) + 'at ' + str(mount_point) + ' with command: ' + str(cmd))
                
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=3600)
            if rtncode != 0:
                self.log.error('rtncode: ' + str(rtncode) + ', Failed to format iSCSI targets for device (' +
                          str(device) + ' with command: ' + str(cmd))
                self.log.error('stdout: ' + str(data_stdout))
                self.log.error('stderr: ' + str(data_stderr))
                return
        except Exception as e:
            self.log.error('Exception: Failed to mount iSCSI device (' + str(device) + ') with command: ' +
                      str(cmd) + " " + str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))

    def __updateRouter(self, isRtr):
        if isRtr == 'user':
           self.log.info("Router: user controlled")
           return

        f = open('/proc/sys/net/ipv4/ip_forward','w')
        if isRtr == 'true':
            self.log.info("Router Yes")
            f.write('1')
        elif isRtr == 'false':
            self.log.info("Router No")
            f.write('0')
        else:
            self.log.info("Unknown Router value: " + str(isRtr))
        f.close()

    def __addRoute(self, network, router):
        args = ''
        command = 'ip'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                cmd = '%s %s route add  %s via %s 2>/dev/null' % (executable, args, network, router)
                self.log.info("Add route: " + str(cmd))
                pipe = os.popen(cmd)
            except IOErExror:
                continue

    def __delRoute(self, network):
        args = ''
        command = 'ip'
        for dir in ['', '/sbin/', '/usr/sbin']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue

            try:
                self.log.info("Deleting route:  " +  '%s %s del %s 2>/dev/null' % (executable, args, network))
                cmd = '%s %s route del %s 2>/dev/null' % (executable, args, network)
                pipe = os.popen(cmd)
            except IOError:
                continue

    def __updateRoute(self, network, router):
        try:
            IPNetwork(network)
        except:
            self.log.error("NEuca: network not in cidr (" + str(network) + ")")

        if router == 'down':
            self.log.info('route down: ' + str(network) + " " + str(router))
            self.__delRoute(network)
        elif router == 'user':
            pass
        else:
            try:
                IPAddress(router)
            except:
                self.log.error("NEuca: router not in valid format ("+ str(router) + "), or invalid state.")
                return
            self.log.info('route up: ' + str(network) + " " + str(router))
            self.__delRoute(network)
            self.__addRoute(network, router)

    def __rescanPCI(self):
	try:
 	    fd = open("/sys/bus/pci/rescan", 'w')
            fd.write('1')
            fd.close()
	except:
	    self.log.error("failed to rescanPCI")

    def __updateHostsFile(self, loopbackAddress, hostName):
        """
        Maintains the loopback entries added to /etc/hosts for novice users.
        """
        neucaStr = "NEuca loopback modifications - DO NOT EDIT BETWEEN THESE LINES. ###\n"
        startStr = "### BEGIN " + neucaStr
        endStr = "### END " + neucaStr

        fd = None
        try:
            fd = open(self.hostsFile, 'r+')
        except:
            self.log.error("Unable to open " + self.hostsFile + " for modifications!")
            return

        hostsEntries = list(fd)
        modified = False

        neucaEntry = None
        try:
            neucaEntry = hostsEntries.index(startStr)
        except ValueError:
            pass

        newHostsEntry = loopbackAddress + "\t" + hostName + "\n"
        if neucaEntry:
            if (hostsEntries[neucaEntry + 1] != newHostsEntry):
                hostsEntries[neucaEntry + 1] = newHostsEntry
                modified = True
        else:
            hostsEntries.append("\n")
            hostsEntries.append(startStr)
            hostsEntries.append(newHostsEntry)
            hostsEntries.append(endStr)
            hostsEntries.append("\n")
            modified = True

        if modified:
            try:
                fd.seek(0)
                fd.truncate()
                for line in hostsEntries:
                    fd.write(line)
            except:
                self.log.error("Error writing modifications to " + self.hostsFile)

    def updateNetworking(self):
        """
        Add/remove network interfaces using ifconfig, etc. 
        """
        super(NEucaLinuxCustomizer, self).updateNetworking()

        self.__rescanPCI()

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
            self.__updateInterface(mac, ip, state)

        #update routes
        self.__updateRouter(self.isRouter())
        routes = self.getAllRoutes()
        for route in routes:
            self.__updateRoute(route[0], route[1])
    
    def runNewScripts(self):
        #self.userData.updateUserData()
        for i in  self.getAllScripts():
            script = NeucaScript(i[0], i[1])
        
    def updateStorage(self):
        iscsi_iqn = self.getISCSI_iqn()

        self.log.debug('iscsi_iqn = ' + str(iscsi_iqn))

        self.__updateISCSI_initiator(iscsi_iqn)

        storage_list = self.userData.getAllStorage()
        
        for device in storage_list:
            #self.log.debug("Storage Device: " + str(device))
            dev_name = device[0]

            if self.__checkISCSI_handled(dev_name):
                self.log.debug('Skipping previously handled storage device: ' + str(dev_name))
                continue

            proto = device[1].split(':')[0]
            if proto == 'iscsi':
                try:
                    ip = device[1].split(':')[1]
                    port = device[1].split(':')[2]
                    #target = device[1].split(':')[3]
                    targets = self.__ISCSI_discover(ip, port)
                    if not targets or len(targets) < 1:
                        self.log.error('Exception: Failed to discover iSCSI targets for device (' + str(ip) + ')')
                        targets = 'Failed to discover iSCSI'

                    lun = device[1].split(':')[3]
                    chap_user = device[1].split(':')[4]
                    chap_pass = device[1].split(':')[5]
                    shouldAttach = device[1].split(':')[6]

                    if len(device[1].split(':')) > 9:
                        fs_type = device[1].split(':')[7]
                        fs_options = device[1].split(':')[8]
                        fs_shouldFormat = device[1].split(':')[9]
                        
                    else:
                        fs_type = None
                        fs_options = None
                        fs_shouldFormat = None

                    if len(device[1].split(':')) > 10:
                        mount_point = device[1].split(':')[10]
                    else:
                        mount_point = None

                    self.log.debug('ip = ' + str(ip))
                    self.log.debug('port = ' +str(port))
                    self.log.debug('targets = ' +str(targets))
                    self.log.debug('lun = ' +str(lun))
                    self.log.debug('chap_user = ' +str(chap_user))
                    self.log.debug('chap_pass = ' +str(chap_pass))
                    self.log.debug('shouldAttach = ' + str(shouldAttach))
                    self.log.debug('fs_type = ' + str(fs_type))
                    self.log.debug('fs_options = ' + str(fs_options))
                    self.log.debug('fs_shouldFormat = ' + str(fs_shouldFormat))
                    self.log.debug('mount_point = ' + str(mount_point))
                
                    target = ''
                    dev_path = ''
                    if shouldAttach.lower() == 'yes':
                        self.log.debug("attaching lun for " + str(dev_name))

                        for target in targets:
                            dev_path = ('/dev/disk/by-path/ip-' + str(ip) + ':' + str(port) +
                                        '-iscsi-' + str(target) +
                                        '-lun-' + str(lun))
                            self.log.debug('dev_path = ' + dev_path)

                            # First, if the LUN has not been attached, attempt to attach it
                            if not os.path.exists(dev_path):
                                self.__updateISCSI_attach(dev_path, target, ip, port, chap_user, chap_pass)

                            # Now, check again to see if the LUN attached.
                            # Attachment *can* transiently fail, for any number of reasons,
                            # so we allow the top-level loop to re-try later.
                            if not os.path.exists(dev_path):
                                continue

                            if fs_shouldFormat.lower() == 'yes' and self.__checkISCSI_shouldFormat(dev_path, fs_type):
                                self.log.debug("formatting fs")
                                self.__updateISCSI_format(dev_path,fs_type,fs_options)
                                pass
                            if not mount_point == None:
                                self.log.debug("mounting fs")
                                self.__updateISCSI_mount(dev_path, fs_type, mount_point)
                                pass
                            break

                        if not os.path.exists(dev_path):
                            self.log.error('iSCSI storage failed. Device ' + str(dev_name) +
                                           ' not attached. Retry next loop.')
                            continue
                    else:
                        self.log.debug("Not attaching lun for " + str(dev_name))

                    #mark storage device handled
                    if not os.path.exists(self.storage_dir):
                        os.makedirs(self.storage_dir)

                    fd = open(self.storage_dir + '/' + dev_name, 'w')
                    fd.write('ip = ' + str(ip) + '\n')
                    fd.write('port = ' +str(port) + '\n')
                    fd.write('target = ' +str(target) + '\n')
                    fd.write('lun = ' +str(lun) + '\n')
                    fd.write('chap_user = ' +str(chap_user))
                    fd.write('chap_pass = ' +str(chap_pass))
                    fd.write('shouldAttach = ' + str(shouldAttach) + '\n')
                    fd.write('fs_type = ' + str(fs_type) + '\n')
                    fd.write('fs_options = ' + str(fs_options) + '\n')
                    fd.write('fs_shouldFormat = ' + str(fs_shouldFormat) + '\n')
                    fd.write('mount_point = ' + str(mount_point) + '\n')
                    fd.write('mount_point = ' + str(mount_point) + '\n')
                    fd.close()

                except Exception as e:
                    self.log.error('Exception in iSCSI storage: ' + str(e) + "\n" + str(type(e)) +
                              "\n" + str(traceback.format_exc()))
                    ip = None
                    port = None
                    target = None
                    lun = None
                    mount_point = None
            else:
                self.log.error('Unknown storage protocol: ' + str(proto))

    def updateHostname(self):
        self.log.debug('updateHostname')

        #get the new hostname
        try:
            new_hostname = self.userData.getHostname()
        except Exception as e:
            self.log.error('Exception getting hostname.  Probably host_name field not in userdata file: ' +
                           str(e) + "\n" + str(type(e)) + "\n" + str(traceback.format_exc())  )
            self.log.error('Not setting hostname')
            return
        
        if new_hostname == None:
            self.log.error('host_name is None.  Not setting host_name')
            return

        #get the old hostname
        try:
            old_hostname = socket.gethostname()
        except:
            old_hostname = None

        self.log.debug('new_hostname = ' + str(new_hostname) + ', old_hostname = ' + str(old_hostname))
        try:
            if new_hostname != old_hostname:
                os.system('/bin/hostname ' + str(new_hostname))
        except Exception as e:
            self.log.error('Exception setting hostname: ' + str(e) + "\n" + str(type(e)) + "\n" + str(traceback.format_exc()))

        if (CONFIG.getboolean('runtime', 'set-loopback-hostname')):
            loopback_address = CONFIG.get('runtime', 'loopback-address')
            if (all_matching_cidrs(loopback_address, [IPV4_LOOPBACK_NET])):
                self.__updateHostsFile(loopback_address, new_hostname)
            else:
                self.log.warn('Specified address not in loopback range; address specified was: ' + loopback_address)

    def updateUserData(self):
	self.userData.update()

    def buildIgnoredMacSet(self):
        mac_string = CONFIG.get('runtime', 'dataplane-macs-to-ignore')
        mac_string = mac_string.replace(' ', '')
        mac_list = mac_string.split(",")
        for mac in mac_list:
            if mac:
                mac_cleaned = mac.lower().replace(':', '')
                self.ignoredMacSet.add(mac_cleaned)
                self.log.debug('Added MAC ' + str(mac) + ' to ignored list.')
        
    def getAllUserData(self):
        return self.userData.getAllUserData()

    def getField(self, section, field):
        return self.userData.get(section,field)


class NEucaRedhatCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        import platform
        distro_version = int(platform.dist()[1].split('.')[0])
	if ((distro == 'fedora') and (distro_version >= 15)) or (((distro == 'redhat') or (distro == 'centos')) and (distro_version >= 7)):
            super(NEucaRedhatCustomizer, self).__init__(distro, 'iscsid')
        else:
            super(NEucaRedhatCustomizer, self).__init__(distro, 'iscsi')


class NEucaDebianCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        super(NEucaDebianCustomizer, self).__init__(distro, 'open-iscsi')


class NEucad():
    def __init__(self):
        self.stateDir = CONFIG.get('runtime', 'state-directory')
        self.pidDir = CONFIG.get('runtime', 'pid-directory')

        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = (self.pidDir +
                             '/' +
                             CONFIG.get('runtime', 'pid-file'))
        self.pidfile_timeout = 5
        
        self.distro = neuca.__distro__
        self.log = logging.getLogger(LOGGER)
        self.customizer = None

        # Need to ensure that the state directory is created.
        if not os.path.exists(self.stateDir):
            os.makedirs(self.stateDir)

        # Ditto for PID directory.
        if not os.path.exists(self.pidDir):
            os.makedirs(self.pidDir)

    def run(self):
        self.log.info('distro: ' + str(self.distro))
        self.customizer.buildIgnoredMacSet()

        while True:
            try:
                self.log.debug("Polling")
		self.customizer.updateUserData()
                self.customizer.updateHostname()
                self.customizer.updateNetworking()
                self.customizer.updateStorage()
                self.customizer.runNewScripts()
	    except KeyboardInterrupt:
                self.log.error("Exception: KeyboardInterrupt")
		sys.exit(0)
	    except Exception as e:
		self.log.debug("Exception in loop: " + str(type(e)) + "\n" + str(traceback.format_exc())  )
            time.sleep(10) 
        

def main():
    head, invokeName = os.path.split(sys.argv[0])

    if invokeName == "neuca":
	print "Invoke as one of the following:"
	print "\tneuca-netconf - to configure host networking"
	print "\tneuca-user-script - to retrieve initial user-specified post-boot script"
	print "\tneuca-all-user-scripts - to retrieve all user-specified post-boot scripts"
        print "\tneuca-run-scripts - to execute any newly created user-specified post-boot scripts"
        print "\tneuca-user-data - to retrieve full user data"
        print "\tneuca-get - to retrieve specific items from user data"
        print "\tneuca-routes - to show whether host has been specified as a router, and get all routes"
        print "\tneuca-get-public-ip - to show the public IP of the host"
        print "\tneuca-distro - to check distribution detection"
        print "\tneuca-version - to report the version of neuca in use"
        sys.exit(0)

    if invokeName == "neuca-distro":
        print neuca.__distro__
        sys.exit(0)

    # choose which OS
    customizer = { 
        "debian": NEucaDebianCustomizer,
        "Ubuntu": NEucaDebianCustomizer,
        "redhat": NEucaRedhatCustomizer,
        "fedora": NEucaRedhatCustomizer,
	"centos": NEucaRedhatCustomizer,
    }.get(neuca.__distro__, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(neuca.__distro__)

    customizer.updateUserData()

    if invokeName == "neuca-netconf":
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

    if invokeName == "neuca-get-public-ip":
        print customizer.getPublicIP()

    if invokeName == "neuca-get":
        argv = sys.argv[1:]
        if len(argv) >= 2:
            section = argv[0]
            field = argv[1]
        elif (len(argv) == 1):
            section = 'global'
            field = argv[0]
        else:
            print 'usage: neuca-get [section] <field>'
            print "section defaults to 'global' if left unassigned"
            sys.exit(0)

        print customizer.getField(section, field)

    if invokeName == "neuca-version":
        print 'NEuca version ' + neuca.__version__

    if invokeName == "neucad":
        usagestr = "Usage: %prog start|stop|restart [options]"
        parser = OptionParser(usage=usagestr)
        parser.add_option("-f", "--foreground", dest="foreground",
                          action="store_true", default=False,
                          help="Run the storage service in foreground (useful for debugging).")
        parser.add_option("-c", "--conffile", dest="config_file", metavar="CONFFILE",
                          help="Read configuration from file CONFFILE, rather than the default location.")

        options, args = parser.parse_args()

        if len(args) != 1:
            parser.print_help()
            sys.exit(1)

        initial_log_location = '/dev/tty'
        try:
            logfd = open(initial_log_location, 'r')
        except:
            initial_log_location = '/dev/null'
        else:
            logfd.close()

        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(format=log_format, filename=initial_log_location)

        config_file = neuca.__ConfDir__ + '/' + neuca.__ConfFile__
        if options.config_file:
            config_file = options.config_file

        try:
            files_read = CONFIG.read(config_file)
            if len(files_read)  == 0:
                logging.warn("Configuration file could not be read; proceeding with default settings.")
        except Exception as e:
            logging.error("Unable to parse configuration file \"%s\": %s"
                          % (config_file, str(e)))
            logging.error("Exiting...")
            sys.exit(1)

        log = logging.getLogger(LOGGER)
        log.setLevel(getattr(logging, CONFIG.get('logging', 'log-level')))

        app = NEucad()
        app.customizer = customizer
        daemon_runner = runner.DaemonRunner(app)

        if options.foreground:
            if runner.is_pidfile_stale(daemon_runner.pidfile):
                daemon_runner.pidfile.break_lock()

            try:
                daemon_runner.pidfile.acquire()
            except LockTimeout:
                log.error("PID file %(app.pidfile_path)r already locked. Exiting..." % vars())
                sys.exit(1)

            try:
                log.info("Running service in foreground mode. Press Control-c to stop.")
                app.run()
            except KeyboardInterrupt:
                log.info("Stopping service at user request (via keyboard interrupt). Exiting...")
                sys.exit(0)
        else:
            if args[0] == 'start':
                sys.argv = [sys.argv[0], 'start']
            elif args[0] == 'stop':
                sys.argv = [sys.argv[0], 'stop']
            elif args[0] == 'restart':
                sys.argv = [sys.argv[0], 'restart']
            else:
                parser.print_help()
                sys.exit(1)
 
            log_dir = CONFIG.get('logging', 'log-directory')
            log_level = CONFIG.get('logging', 'log-level')

            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            handler = logging.handlers.RotatingFileHandler(log_dir + '/' + CONFIG.get('logging', 'log-file'),
                                                           backupCount = CONFIG.getint('logging', 'log-retain'),
                                                           maxBytes = CONFIG.getint('logging', 'log-file-size'))
            handler.setLevel(getattr(logging, log_level))
            formatter = logging.Formatter(log_format)
            handler.setFormatter(formatter)
    
            log.addHandler(handler)
            log.propagate = False
            log.info("Logging Started")
 
            daemon_runner.daemon_context.files_preserve = [ handler.stream, ]
            try:
                log.info("Administrative operation: %s" % args[0])
                daemon_runner.do_action()
            except runner.DaemonRunnerStopFailureError, drsfe:
                log.propagate = True
                log.error("Unable to stop service; reason was: %s" % str(drsfe))
                log.error("Exiting...")
                sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
