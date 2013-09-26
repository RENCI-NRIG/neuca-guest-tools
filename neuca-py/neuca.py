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
import subprocess

import boto.utils
import ConfigParser
import ipaddr
import platform
import traceback
import re

from netaddr import *

import socket

from subprocess import *
from os import kill
from signal import alarm, signal, SIGALRM, SIGKILL
from subprocess import PIPE, Popen


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

class Commands:
    @classmethod
    def run_cmd(self, args):
        cmd = args
        LOG.debug("running command: " + " ".join(cmd))
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

        LOG.debug("run: args= " + str(args))
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
        LOG.debug('Creating NeucaScript: ' + name + "--" + script)

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
                #cmd = '%s 2>/dev/null' % (executable)
                cmd = str(executable)
                LOG.info("Running: " + str(cmd))
                #pipe = os.popen(cmd)
                subprocess.Popen(["nohup", cmd])
            except IOError:
                pass

class NEucaUserData(object):
    def __init__(self):
	self.userData=None
        # TODO:  change back for real VM 
        #self.userData=boto.utils.get_instance_userdata()
        
        #fh = TempFile(prefix='euca-n-userdata')
        #fh.write(self.userData)
        #fh.close()
        
        #self.config = ConfigParser.RawConfigParser()
        #self.config.read(fh.path)
	pass

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
        self.userData = NEucaUserData()
        #if self.userData.empty():
        #    LOG.warning("Unable to retrieve NEuca user data")
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
    networkConfigurationFile = '/etc/network/interfaces'
    
    iscsiInitScript='open-iscsi'
    
    def __init__(self, distro):
        super(NEucaLinuxCustomizer, self).__init__(distro)
        

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

    def __checkISCSI_shouldFormat(self, device, fs_type):
        LOG.debug('__updateISCSI_shouldFormat(self, '+device+', '  + fs_type +')')
        import os
        current_fs_type=None
        args = ''
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
            LOG.error('blkid executable does not exist in paths ., /sbin, or /usr/sbin.  Cannot check for existing fs_type.  Will not format disk')
            return False

        try:
            cmd = [ str(executable),  str(device) ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)

            if rtncode == 2:
                #disk unformated
                LOG.debug('shouldFormat -> True, disk is unformated: ' + str(device))
                return True

            if rtncode != 0:
                LOG.error('rtncode: ' + str(rtncode) + 'Failed to test for device filesystem (' + str(device) + ' with command: ' + str(cmd))
                LOG.error('Cannot check for existing fs_type.  Will not format disk')
                return False

            for v in data_stdout.split(' '):
                if v.split('=')[0] != 'TYPE':
                    continue

                if len(v.split('=')) > 1 and v.split('=')[0] == 'TYPE':
                    current_fs_type = v.split('=')[1]
                    if current_fs_type  == '"' + fs_type + '"':
                       #found match
                        LOG.debug('shouldFormat -> False, disk is formated with desired fs_type: ' + str(device) + ', ' + str(fs_type))
                        return False
                break
            
        except Exception as e:
            LOG.error('Exception: Failed to test for device filesystem. Cannot check for existing fs_type.  Will not format disk (' + str(device) + ') with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))

        LOG.debug('shouldFormat -> True, disk is formated with ' + str(current_fs_type) + ': ' + str(device) + ', ' + str(fs_type))
        return True




    def __checkISCSI_handled(self, device_entry):
        base_path = '/var/run/neuca/storage'

        if os.path.exists(str(base_path) + '/' + str(device_entry)):
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
                        LOG.warning("__updateISCSI_initiator: new and old iqn are the same (" + str(new_initiator_iqn) +  "), not updating.")
                        return
                    else:
                        index = lines.index(line)
                        LOG.debug('line: ' + str(line) +', lines[' + str(index) + ']: ' + str(lines[index]))
                        lines[index] = '##' + line
                        lines.insert(index+1,'InitiatorName=' + str(new_initiator_iqn) + '\n') 
                        found = True
                        break
        
        if not found:
            lines.append('InitiatorName=' + str(new_initiator_iqn) + '\n')

        LOG.debug('initiatorname (lines): ' + str(lines))
                          
        #stop open iscsi
        import os
        args = ''
        command = self.iscsiInitScript
        exeExists=False
        for dir in ['', '/etc/init.d']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            LOG.error('open-iscsi init.d script does not exist in paths ., /etc/init.d')
            return

        try:
            #/etc/init.d/open-iscsi stop                                                                                                                                                                                  
            cmd = [ str(executable), "stop" ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                LOG.error('rtncode: ' + str(rtncode) + 'Failed to shutdown open-iscsi with command: ' + str(cmd))
                return None

        except Exception as e:
            LOG.error('Exception: Failed to shutdown open-iscsi with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return

        #update initiator file
        f = open('/etc/iscsi/initiatorname.iscsi','w')
        for line in lines:
            f.write(str(line) + '\n')
        f.close()

        #start open iscsi
        args = ''
        command = self.iscsiInitScript
        exeExists=False
        for dir in ['', '/etc/init.d']:
            executable = os.path.join(dir, command)
            if not os.path.exists(executable):
                continue
            else:
                exeExists=True
                break

        if not exeExists:
            LOG.error('open-iscsi init.d script does not exist in paths ., /etc/init.d')
            return

        try:
            #/etc/init.d/open-iscsi start
            cmd = [ str(executable), "start" ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                LOG.error('rtncode: ' + str(rtncode) + 'Failed to start open-iscsi with command: ' + str(cmd))
                return None

        except Exception as e:
            LOG.error('Exception: Failed to start open-iscsi with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return

        #clean up files from previous mounts, rm /var/run/neuca/storage/*
        for f in os.listdir('/var/run/neuca/storage'):
            LOG.debug('Removing file: ' + str(f))
            os.remove('/var/run/neuca/storage/' + f)
        


    def __ISCSI_discover(self, ip):
	LOG.debug('__ISCSI_discover(self, ' + str(ip) )
        import os
        args = ''
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
            LOG.error('iSCSI executable iscsiadm does not exist in paths ., /bin, or /usr/bin')
            return None

        try:
            #discover targets: iscsiadm --mode discovery --type sendtargets --portal 172.16.101.43
            cmd = [ str(executable), "--mode", "discovery", "--type", "sendtargets", "--portal", str(ip) ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                LOG.error('rtncode: ' + str(rtncode) + 'Failed to discover iSCSI targets with command: ' + str(cmd))
                return None

            LOG.debug('Targets: ' + str(data_stdout))
        except Exception as e:
            LOG.error('Exception: Failed to discover iSCSI targets for device with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return None
	
	lines = data_stdout.split('\n')
        for line in lines:
            if line.strip().startswith(str(ip)):
		line_split = line.split()
		LOG.debug('line_split: ' + str(line_split))
		if len(line_split) >= 2:
                    target = line_split[1].strip()
                    LOG.debug('return target: ' + target)
                    return target
                
        LOG.debug('return target: None')
	return None

    def __updateISCSI_attach(self, device, target, ip, port, chap_user, chap_pass):
        LOG.debug('__updateISCSI_target_login(self, '+ str(device) +', ' + str(target)  + ', ' + str(ip)  + ', ' + str(port) +')')
        import os
        args = ''
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
            LOG.error('iSCSI executable iscsiadm does not exist in paths ., /bin, or /usr/bin')
            return

                #Attach the device is it is not already attached                                                                                                                                                                                                                            
        if not os.path.exists(device):
            #iSCSI device not attached                                                                                                                                                                                                                                              

            #set authmethod : iscsiadm --mode node --targetname target0 --portal 172.16.101.43:3260 --op=update --name node.session.auth.authmethod --value=CHAP                                                                                                                    
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip)+":"+str(port), "--op=update", "--name", "node.session.auth.authmethod", "--value=CHAP" ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    LOG.error('rtncode: ' + str(rtncode) + 'Failed to set iSCSI authmethod device (' + str(device) + ' with command: ' + str(cmd))
                    return
            except Exception as e:
                LOG.error('Exception: Failed to set iSCSI authmethod device  (' + str(device) + ') with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
                return

            #set chap username : iscsiadm --mode node --targetname target0 --portal 172.16.101.43:3260 --op=update --name node.session.auth.username --value=username                                                                                                               
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip)+":"+str(port), "--op=update", "--name", "node.session.auth.username", "--value="+str(chap_user) ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    LOG.error('rtncode: ' + str(rtncode) + 'Failed to set iSCSI chap user for device (' + str(device) + ' with command: ' + str(cmd))
                    return
            except Exception as e:
                LOG.error('Exception: Failed to set iSCSI chap user for device  (' + str(device) + ') with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
                return

            #set chap password : iscsiadm --mode node --targetname target0 --portal 172.16.101.43:3260 --op=update --name node.session.auth.password --value=password                                                                                                               
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip)+":"+str(port), "--op=update", "--name", "node.session.auth.password", "--value="+str(chap_pass) ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    LOG.error('rtncode: ' + str(rtncode) + 'Failed to set iSCSI chap password device (' + str(device) + ' with command: ' + str(cmd))
                    return
            except Exception as e:
                LOG.error('Exception: Failed to set iSCSI chap pass device  (' + str(device) + ') with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
                return

            #attach target: iscsiadm --mode node --targetname target0  --portal 172.16.101.43:3260   --login                                                                                                                                                                        
            try:
                cmd = [ str(executable), "--mode", "node", "--targetname", str(target), "--portal", str(ip)+":"+str(port), '--login' ]
                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
                if rtncode != 0:
                    LOG.warning('rtncode: ' + str(rtncode) + 'Failed to attach iSCSI target for device (' + str(device) + ' with command: ' + str(cmd))
                    self.__updateISCSI_target_rescan(device, target, ip, port)
                else:
                    LOG.debug('Attach stdout: ' +str(data_stdout))
            except Exception as e:
                LOG.error('Failed to connect iSCSI device (' + str(device) + ' with command: ' + str(cmd))
                self.__updateISCSI_target_rescan(device, target, ip, port)
        else:
            LOG.debug('Device already connected: ' + str(device))
            return

        LOG.debug('Checking device attached: ' + str(device))
        count = 0
        while not os.path.exists(device):
            LOG.debug('Device not attached: ' + str(device) + ', try ' + str(count))
            count = count + 1
            if count > 10:
                break
            time.sleep(1)

    def __updateISCSI_target_rescan(self, device, target, ip, port):
        LOG.debug('__updateISCSI_target_rescan(self, ' + str(device) +', ' + str(target)  + ')')
        import os
        args = ''
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
            LOG.error('iSCSI executable iscsiadm does not exist in paths ., /bin, or /usr/bin')
            return

        #iscsiadm -m discovery -t st -p 10.104.0.2 -o delete -o new
        try:
            cmd = [ str(executable), "-m", "discovery", "-t", "st", "--portal", str(ip)+":"+str(port), "-o", "delete", "-o", "new" ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                LOG.error('rtncode: ' + str(rtncode) + 'Failed re-discovery with command: ' + str(cmd))
                return
        except Exception as e:
            LOG.error('Exception: Failed re-discovery with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return
         
        #iscsiadm -m session --rescan          
        try:
            cmd = [ str(executable), "--mode", "session", "--rescan" ]
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                LOG.error('rtncode: ' + str(rtncode) + 'Failed to rescan with command: ' + str(cmd))
                return
        except Exception as e:
            LOG.error('Exception: Failed to rescan with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
            return

        LOG.debug('Checking device attached: ' + str(device))
        count = 0
        while not os.path.exists(device):
            LOG.debug('Device not attached: ' + str(device) + ', try ' + str(count))
            count = count + 1
            if count > 10:
                break
            time.sleep(1)
        

    def __updateISCSI_format(self, device, fs_type, fs_options):
        LOG.debug('__updateISCSI_format(self, '+device+', ' + fs_type  + ', ' + fs_options + ')')
        import os
        args = ''
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
            LOG.error('Executable mkfs does not exist in paths ., /sbin, or /usr/sbin')
            return
        
        if os.path.exists(device):
            try:
              
                cmd = [ str(executable), "-t", fs_type ]
                for option in re.split('\s+', fs_options):  
                    cmd.append(str(option))
                cmd.append(str(device))

                LOG.info('Formating iSCSI device ' + str(device) + ' with command: ' + str(cmd))

                rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=3600)
                if rtncode != 0:
                    LOG.error('rtncode: ' + str(rtncode) + ', Failed to format iSCSI targets for device (' + str(device) + ' with command: ' + str(cmd))
                    LOG.error('stdout: ' + str(data_stdout))
                    LOG.error('stderr: ' + str(data_stderr))
                    return

            except Exception as e:
                LOG.error('Exception: Failed to format iSCSI targets for device (' + str(device) + ') with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))
        else:
            LOG.debug('iSCSI device not attached: ' + str(device))

    def __updateISCSI_mount(self, device, fs_type, mount_point):
        LOG.debug('__updateISCSI_mount(self, '+device+', ' + fs_type + ', ' + mount_point  + ')')
        import os
        args = ''
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
            LOG.error('Executable mount does not exist in paths ., /bin, or /usr/bin')
            return
        
        #Mount the file system
        if not os.path.exists(device):
            LOG.debug('Failed to mount device because iSCSI device not attached: ' + str(device))
            return

        LOG.debug('Checking dir: ' + str(mount_point))
        try:
            os.makedirs(str(mount_point))
            LOG.debug('Created ' + str(mount_point))
        except OSError as exception:
            LOG.debug('Mount point exists: ' + str(mount_point))


        try:
            cmd = [ str(executable), "-t", str(fs_type), str(device), str(mount_point)]
   
            LOG.info('Mounting iSCSI device ' + str(device) + 'at ' + str(mount_point) + ' with command: ' + str(cmd))
                
            rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=3600)
            if rtncode != 0:
                LOG.error('rtncode: ' + str(rtncode) + ', Failed to format iSCSI targets for device (' + str(device) + ' with command: ' + str(cmd))
                LOG.error('stdout: ' + str(data_stdout))
                LOG.error('stderr: ' + str(data_stderr))
                return
            
        except Exception as e:
            LOG.error('Exception: Failed to mount iSCSI device (' + str(device) + ') with command: ' + str(cmd) + " " +  str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))

            

    def __updateRouter(self, isRtr):
        if isRtr == 'user':
           LOG.info("Router: user controlled")
           return

        f = open('/proc/sys/net/ipv4/ip_forward','w')
        if isRtr == 'true':
            LOG.info("Router Yes")
            f.write('1')
        elif isRtr == 'false':
            LOG.info("Router No")
            f.write('0')
        else:
            LOG.info("Unknown Router value: " + str(isRtr))
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
            except IOErExror:
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

    def __rescanPCI(self):
	try:
 	    fd = open("/sys/bus/pci/rescan", 'w')
            fd.write('1')
            fd.close()
	except:
	    LOG.error("failed to rescanPCI")

    def updateNetworking(self):
        """
        Add/remove newtork interfaces using ifconfig, etc. 
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
            self.__updateInterface(mac,ip,state)

        #update routes
        self.__updateRouter(self.isRouter())
        routes = self.getAllRoutes()
        for route in routes:
            self.__updateRoute(route[0],route[1])
    
    def runNewScripts(self):
        import time
        #self.userData.updateUserData()

        for i in  self.getAllScripts():
            script = NeucaScript(i[0],i[1])
        
    def updateStorage(self):

        iscsi_iqn = self.getISCSI_iqn()

        LOG.debug('iscsi_iqn = ' + str(iscsi_iqn))

        self.__updateISCSI_initiator(iscsi_iqn)

        storage_list = self.userData.getAllStorage()
        
        for device in storage_list:
            #LOG.debug("Storage Device: " + str(device))
            dev_name = device[0]

            if self.__checkISCSI_handled(dev_name):
                LOG.debug('Skipping previously handled storage device: ' + str(dev_name))
                continue

            proto = device[1].split(':')[0]
            if proto == 'iscsi':
                try:
                    ip = device[1].split(':')[1]
                    port = device[1].split(':')[2]
                    #target = device[1].split(':')[3]
                    target = self.__ISCSI_discover(ip)
                    if target == None:
                        LOG.error('Exception: Failed to discover iSCSI targets for device (' + str(ip) + ')')
                        target == 'Failed to discover iSCSI'

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

                    LOG.debug('ip = ' + str(ip))
                    LOG.debug('port = ' +str(port))
                    LOG.debug('target = ' +str(target))
                    LOG.debug('lun = ' +str(lun))
                    LOG.debug('chap_user = ' +str(chap_user))
                    LOG.debug('chap_pass = ' +str(chap_pass))
                    LOG.debug('shouldAttach = ' + str(shouldAttach))
                    LOG.debug('fs_type = ' + str(fs_type))
                    LOG.debug('fs_options = ' + str(fs_options))
                    LOG.debug('fs_shouldFormat = ' + str(fs_shouldFormat))
                    LOG.debug('mount_point = ' + str(mount_point))
                
                    device = '/dev/disk/by-path/ip-' + str(ip) + ':' + str(port) + '-iscsi-' + str(target) + '-lun-' + str(lun)

                    LOG.debug('device = ' + device)

                    if shouldAttach.lower() == 'yes':
                        LOG.debug("attaching lun")
                        if not os.path.exists(device):
                            #self.__updateISCSI_target_rescan(device, target, ip, port)
                            self.__updateISCSI_attach(device, target, ip, port, chap_user, chap_pass)
                        if fs_shouldFormat.lower() == 'yes' and self.__checkISCSI_shouldFormat(device, fs_type):
                            LOG.debug("formatting fs")
                            self.__updateISCSI_format(device,fs_type,fs_options)
                            pass
                        if not mount_point == None:
                            LOG.debug("mounting fs")
                            self.__updateISCSI_mount(device, fs_type, mount_point)
                            pass
                    
                    if not os.path.exists(device):
                        LOG.error('iSCSI storage failed.  Device not attached.  Retry next loop')
                        return
                    
                    #mark storage device handled
                    storage_dir='/var/run/neuca/storage'
                    
                    if not os.path.exists(storage_dir):
                        os.makedirs(storage_dir)

                    fd = open(storage_dir + '/' + dev_name, 'w')
                    fd.write('ip = ' + str(ip) + '\n')
                    fd.write('port = ' +str(port) + '\n')
                    fd.write('target = ' +str(target) + '\n')
                    fd.write('lun = ' +str(lun) + '\n')
                    fd.write('target = ' +str(chap_user))
                    fd.write('lun = ' +str(chap_pass))
                    fd.write('shouldAttach = ' + str(shouldAttach) + '\n')
                    fd.write('fs_type = ' + str(fs_type) + '\n')
                    fd.write('fs_options = ' + str(fs_options) + '\n')
                    fd.write('fs_shouldFormat = ' + str(fs_shouldFormat) + '\n')
                    fd.write('mount_point = ' + str(mount_point) + '\n')
                    fd.write('mount_point = ' + str(mount_point) + '\n')
                    fd.close()

                except Exception as e:
                    LOG.error('Exception in iSCSI storage: ' + str(e) + "\n" + str(type(e)) + "\n" + str(traceback.format_exc())  )
                    ip = None
                    port = None
                    target = None
                    lun = None
                    mount_point = None
            else:
                LOG.error('Unknown storage protocol: ' + str(proto))
                    

    def updateHostname(self):
        LOG.debug('updateHostname')

        #get the new hostname
        try:
            new_hostname = self.userData.getHostname()
        except:
            LOG.error('Exception getting hostname.  Probably host_name field not in userdata file: ' + str(e) + "\n" + str(type(e)) + "\n" + str(traceback.format_exc())  )
            LOG.error('Not setting hostname')
            return
        
        if new_hostname == None:
            LOG.error('host_name is None.  Not setting host_name')
            return

        #get the old hostname
        try:
            old_hostname = socket.gethostname()
        except:
            old_hostname = None

        LOG.debug('new_hostname = ' + str(new_hostname) + ', old_hostname = ' + str(old_hostname))
        try:
            if new_hostname != old_hostname:
                os.system('/bin/hostname ' + str(new_hostname))
        except:
            LOG.error('Exception setting hostname: ' + str(e) + "\n" + str(type(e)) + "\n" + str(traceback.format_exc())  )

    def updateUserData(self):
	self.userData.updateUserData()
        
    def getAllUserData(self):
        return self.userData.getAllUserData()

    def getField(self, section, field):
        return self.userData.get(section,field)

class NEucaRedhatCustomizer(NEucaLinuxCustomizer): 
    def __init__(self, distro):
        super(NEucaRedhatCustomizer, self).__init__(distro)
        iscsiInitScript='iscsi'

class NEucaFedoraCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        super(NEucaFedoraCustomizer, self).__init__(distro)
        iscsiInitScript='iscsi'

class NEucaCentosCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        super(NEucaCentosCustomizer, self).__init__(distro)
        iscsiInitScript='iscsi'

class NEucaDebianCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        super(NEucaDebianCustomizer, self).__init__(distro)
        iscsiInitScript='open-iscsi'

class NEucaUbuntuCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        super(NEucaUbuntuCustomizer, self).__init__(distro)
        iscsiInitScript='open-iscsi'

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
            "redhat": NEucaLinuxCustomizer,
            "fedora": NEucaLinuxCustomizer,
            "centos": NEucaLinuxCustomizer,
        }.get(self.distro, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(self.distro)


        self.customizer.initLogging()

        while True:
            try:
                LOG.debug("Polling")
		self.customizer.updateUserData()
                self.customizer.updateHostname()
                self.customizer.updateNetworking()
                self.customizer.updateStorage()
                self.customizer.runNewScripts()
	    except KeyboardInterrupt:
                LOG.error("Exception: KeyboardInterrupt")
		sys.exit(0)
	    except Exception as e:
		LOG.debug("Exception in loop: " + str(type(e)) + "\n" + str(traceback.format_exc())  )
            time.sleep(10) 

        

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
        "debian": NEucaLinuxCustomizer,
        "Ubuntu": NEucaLinuxCustomizer,
        "redhat": NEucaLinuxCustomizer,
        "fedora": NEucaLinuxCustomizer,
	"centos": NEucaLinuxCustomizer,
    }.get(distro, lambda x: sys.stderr.write("Distribution " + x + " not supported\n"))(distro)

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
            print 'usage: necua-get [section] <field>'
            print "section defaults to 'global' if left unassigned"
            sys.exit(0)

        print customizer.getField(section,field)

    if invokeName == "neuca-version":
        print 'NEuca version 1.3'


    if invokeName == "neucad":
        app = NEucad()
        daemon_runner = runner.DaemonRunner(app)
        daemon_runner.do_action()

    

    sys.exit(0)

if __name__ == "__main__":
    main()
    
