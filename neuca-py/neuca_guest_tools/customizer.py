# Copyright (c) 2017 Renaissance Computing Institute, except where noted.
# All rights reserved.
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
# Author: Ilya Baldin (ibaldin@renci.org)
# Author: Paul Ruth (pruth@renci.org)
# Author: Victor J. Orlikowski (vjo@duke.edu)

import os
import re
import socket
import subprocess
import time
import glob
import json

from neuca_guest_tools import CONFIG, LOGGER
from neuca_guest_tools import _IPV4_LOOPBACK_NET as loopbackNet
from neuca_guest_tools import _StorageDir as neuca_StorageDir
from neuca_guest_tools import _UdevDirectory as default_udev_directory
from neuca_guest_tools import _UdevSubstring as default_udev_substring
from neuca_guest_tools import _MgmtUdevPriority as default_mgmt_udev_priority
from neuca_guest_tools import _DataUdevPriority as default_data_udev_priority
from neuca_guest_tools.instancedata import NEucaInstanceData
from neuca_guest_tools.script import NeucaScript
from neuca_guest_tools.util import Commands

import logging

from netaddr import IPAddress, IPNetwork, all_matching_cidrs


# For now, let's keep customizer selection primitive.
def get_customizer(distro):
    customizers = {
        'debian': NEucaDebianCustomizer,
        'Ubuntu': NEucaDebianCustomizer,
        'redhat': NEucaRedhatCustomizer,
        'fedora': NEucaRedhatCustomizer,
        'centos': NEucaRedhatCustomizer,
    }
    return customizers.get(distro)(distro)


class NEucaOSCustomizer(object):
    """Generic OS customizer """

    def __init__(self, distro):
        self.instanceData = NEucaInstanceData()
        self.log = logging.getLogger(LOGGER)
        self.ignoredMacSet = set()
        self.firstRun = True

    def updateInstanceData(self):
        self.instanceData.updateInstanceData()

    def getInstanceData(self):
        return self.instanceData

    def getBootScript(self):
        return self.instanceData.getBootScript()

    def getAllScripts(self):
        return self.instanceData.getAllScripts()

    def isRouter(self):
        return self.instanceData.isRouter()

    def getISCSI_iqn(self):
        return self.instanceData.getISCSI_iqn()

    def getAllStorage(self):
        return self.instanceData.getAllStorage()

    def getAllUsers(self):
        return self.instanceData.getAllUsers()

    def getAllInterfaces(self):
        return self.instanceData.getAllInterfaces()

    def getAllRoutes(self):
        return self.instanceData.getAllRoutes()

    def getPublicIP(self):
        return self.instanceData.getPublicIP()

    def getUserData(self):
        return self.instanceData.getUserData()

    def getUserDataField(self, section, field):
        return self.instanceData.getUserDataField(section, field)

    def updateNetworking(self):
        pass

    def updateStorage(self):
        pass

    def customizeNetworking(self):
        pass

    def runCustomScript(self):
        pass


class NEucaLinuxCustomizer(NEucaOSCustomizer):
    """Linux customizer """

    def __init__(self, distro, iscsiInitScript):
        super(NEucaLinuxCustomizer, self).__init__(distro)
        self.iscsiInitScript = iscsiInitScript
        self.storage_dir = neuca_StorageDir
        self.hostsFile = '/etc/hosts'
        try:
            self.udevDirectory = CONFIG.get('linux',
                                            'udev-directory')
        except Exception:
            self.udevDirectory = default_udev_directory
        try:
            self.udevSubstring = CONFIG.get('linux',
                                            'udev-substring')
        except Exception:
            self.udevSubstring = default_udev_substring
        try:
            self.udevMgmtPrio = CONFIG.getint('linux',
                                              'mgmt-udev-priority')
        except Exception:
            self.udevMgmtPrio = default_mgmt_udev_priority
        try:
            self.udevDataPrio = CONFIG.getint('linux',
                                              'data-udev-priority')
        except Exception:
            self.udevDataPrio = default_data_udev_priority

    def __findCommandInPaths(self, command, paths):
        """
        Finds a given command in a list of paths.
        Returns the full command path as a string,
        or None if the command was not found.
        """
        executable = None
        for dir in paths:
            executable = os.path.join(dir, command)
            if os.path.exists(executable):
                break
            else:
                executable = None
        return executable

    def __findIfaceByMac(self, mac):
        """
        Gets the interface name for a given mac address

        based on code from uuid.py by Ka-Ping Yee <ping@zesty.ca>
        """

        hw_identifiers = ['link/ether']
        command = 'ip'
        paths = ['./', '/sbin/', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is not None:
            try:
                cmd = [executable, '-o', 'link']
                (rtncode,
                 data_stdout,
                 data_stderr) = Commands.run(cmd, timeout=60)
            except Exception as e:
                self.log.exception('Failed to obtain list of interfaces ' +
                                   'using command: ' + str(cmd))
                self.log.error('Exception was of type: %s' % (str(type(e))))
                return None

            # The "-o" flag in the args ensures one line per interface.
            lines = data_stdout.split('\n')
            for line in lines:
                words = line.lower().split()
                if len(words) == 0:
                    continue
                # The interface name is the second field
                iface = words[1].strip(':')

                for i in range(len(words)):
                    if ((words[i] in hw_identifiers)
                            and (words[i + 1].replace(':', '') == mac)):
                        return iface
        return None

    def __getMacByIface(self, iface):
        """
        Gets the mac address for a given interface name

        based on code from uuid.py by Ka-Ping Yee <ping@zesty.ca>
        """

        hw_identifiers = ['link/ether']
        command = 'ip'
        paths = ['./', '/sbin/', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is not None:
            try:
                cmd = [executable, '-o', 'link']
                (rtncode,
                 data_stdout,
                 data_stderr) = Commands.run(cmd, timeout=60)
            except Exception as e:
                self.log.exception('Failed to obtain list of interfaces ' +
                                   'using command: ' + str(cmd))
                self.log.error('Exception was of type: %s' % (str(type(e))))
                return None

            # The "-o" flag in the args ensures one line per interface.
            lines = data_stdout.split('\n')
            for line in lines:
                words = line.lower().split()
                if len(words) == 0:
                    continue
                # The interface name is the second field
                found_iface = words[1].strip(':')

                if (found_iface == iface):
                    for i in range(len(words)):
                        if (words[i] in hw_identifiers):
                            return words[i + 1].replace(':', '')
        return None

    def __getPhysicalIfacesByMac(self):
        """
        Returns a dict containing all non-loopback interfaces, indexed by MAC

        based on code from uuid.py by Ka-Ping Yee <ping@zesty.ca>
        """

        phyDict = {}

        hw_identifiers = ['link/ether']
        command = 'ip'
        paths = ['./', '/sbin/', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is not None:
            try:
                cmd = [executable, '-o', 'link']
                (rtncode,
                 data_stdout,
                 data_stderr) = Commands.run(cmd, timeout=60)
            except Exception as e:
                self.log.exception('Failed to obtain list of interfaces ' +
                                   'using command: ' + str(cmd))
                self.log.error('Exception was of type: %s' % (str(type(e))))
                return None

            # The "-o" flag in the args ensures one line per interface.
            lines = data_stdout.split('\n')
            for line in lines:
                words = line.lower().split()
                if len(words) == 0:
                    continue
                # The interface name is the second field
                iface = words[1].strip(':')

                for i in range(len(words)):
                    if (words[i] in hw_identifiers):
                        mac = words[i + 1].replace(':', '')
                        phyDict[mac] = iface
        return phyDict

    def __macDisabledByUser(self, mac):
        mac_cleaned = mac.lower().replace(':', '')
        return (mac_cleaned in self.ignoredMacSet)

    def __ifaceChange(self, iface, state, cidr):
        command = 'ip'
        paths = ['./', '/sbin/', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is not None:
            cmd = [
                executable,
                'link', 'set',
                iface, state
            ]
            rtncode = subprocess.call(cmd)
            if rtncode == 0:
                self.log.debug('Changed state for interface %s to: %s'
                               % (iface, state))
            else:
                self.log.warning(('Unable to bring interface %s %s ' +
                                  'at this time.')
                                 % (iface, state))
                return

            if ('up' == state and cidr is not None):
                # We need to assign a CIDR to an interface.
                # We cannot, however, assume that an address
                # has not already been assigned.
                #
                # We therefore check, and only flush/modify the
                # interface when the CIDR assigned to it is
                # different from what we expect.
                #
                # Users desiring multiple CIDRs on a given interface
                # should use the "user" state, or else ensure that
                # the dataplane MAC is in the ignored set, in the
                # configuration file.
                try:
                    cmd = [
                        executable,
                        '-o', 'addr', 'show', 'dev',
                        iface
                    ]
                    (rtncode,
                     data_stdout,
                     data_stderr) = Commands.run(cmd, timeout=60)
                except Exception as e:
                    self.log.exception(('Failed to obtain list of addresses ' +
                                        'for device %s using command: %s')
                                       % (iface, str(cmd)))
                    self.log.error('Exception was of type: %s'
                                   % (str(type(e))))
                    return None

                cidr_found = False
                addr_identifiers = ['inet', 'inet6']
                lines = data_stdout.split('\n')
                for line in lines:
                    words = line.lower().split()
                    for i in range(len(words)):
                        if (words[i] in addr_identifiers
                                and words[i + 1] == cidr):
                            cidr_found = True

                if not cidr_found:
                    cmd = [
                        executable,
                        'addr', 'flush', 'dev',
                        iface
                    ]
                    rtncode = subprocess.call(cmd)
                    if rtncode == 0:
                        self.log.debug(('Flushed addresses on interface ' +
                                        '%s due to change in configuration.')
                                       % iface)
                    else:
                        self.log.warning(('Unable to flush addresses ' +
                                          'on interface %s at this time.')
                                         % iface)
                        return

                    cmd = [
                        executable,
                        'addr', 'add',
                        cidr,
                        'broadcast', '+', 'scope', 'global',
                        'dev',
                        iface
                    ]
                    rtncode = subprocess.call(cmd)
                    if rtncode == 0:
                        self.log.debug('Address %s configured on interface %s'
                                       % (cidr, iface))
                    else:
                        self.log.warning(('Unable to set address %s ' +
                                          'on interface %s at this time.')
                                         % (cidr, iface))
                        return
            elif ('up' == state and cidr is None):
                self.log.debug(('CIDR unset for interface %s, but ' +
                                'state is "%s"; leaving in user control.')
                               % (iface, state))

    def __updateInterface(self, mac, state, cidr):
        iface = self.__findIfaceByMac(mac)

        if (iface is None):
            self.log.warning(('Could not find interface having ' +
                              'MAC address %s at this time.')
                             % mac)
            return

        if (self.__macDisabledByUser(mac)):
            self.log.info(('Interface %s having MAC address ' +
                           '%s is being ignored at user request.')
                          % (iface, mac))
            return

        # config iface
        if (state == 'up' or state == 'down'):
            self.__ifaceChange(iface, state, cidr)
            pass
        elif state == 'user':
            # ignore because user is in control
            pass
        else:
            # unknown state
            self.log.error('NEuca found unknown interface state: %s %s'
                           % (mac, state))

    def __checkISCSI_shouldFormat(self, device, fs_type):
        self.log.debug('__updateISCSI_shouldFormat(self, %s, %s)'
                       % (device, fs_type))
        current_fs_type = None
        command = 'blkid'
        paths = ['./', '/sbin/', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('%s executable does not exist in paths: ' +
                            '%s. Cannot check for existing fs_type; ' +
                            'will not format disk.')
                           % (command, str(paths)))
            return False

        try:
            cmd = [executable, device]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)

            if rtncode == 2:
                # disk unformated
                self.log.debug('shouldFormat -> True, disk is unformatted: %s'
                               % device)
                return True

            if rtncode != 0:
                self.log.error(('rtncode: %s - ' +
                                'Failed to test for device filesystem %s ' +
                                'with command: %s')
                               % (str(rtncode), device, str(cmd)))
                self.log.error('Cannot check for existing fs_type; ' +
                               'will not format disk.')
                return False

            for v in data_stdout.split(' '):
                if v.split('=')[0] != 'TYPE':
                    continue

                if len(v.split('=')) > 1 and v.split('=')[0] == 'TYPE':
                    current_fs_type = v.split('=')[1]
                    if current_fs_type == ('"%s"' % fs_type):
                        # found match
                        self.log.debug(('shouldFormat -> False, disk is ' +
                                        'formatted with desired fs_type: ' +
                                        '%s, %s')
                                       % (device, fs_type))
                        return False
                break
        except Exception as e:
            self.log.exception(('Failed to test for device filesystem; ' +
                                'cannot check for existing fs_type. ' +
                                'Will not format disk (%s) with command: %s')
                               % (device, str(cmd)))
            self.log.error('Exception was of type: %s' % (str(type(e))))

        self.log.debug(('shouldFormat -> True, disk is formatted with %s ; ' +
                        'formatting (%s) as %s')
                       % (str(current_fs_type), device, fs_type))
        return True

    def __checkISCSI_handled(self, device_entry, ip, port, lun,
                             chap_user, chap_pass):
        iscsiDevFile = ('%s/%s' % (self.storage_dir, device_entry))
        fd = None
        if os.path.exists(iscsiDevFile):
            try:
                fd = open(iscsiDevFile, 'r+')
            except Exception:
                self.log.error('Unable to open %s for reading!' % iscsiDevFile)
                return False

            fd.seek(0)
            iscsiDevEntries = list(fd)
            fd.close()

            if (
                    (ip in iscsiDevEntries[0]) and
                    (port in iscsiDevEntries[1]) and
                    (lun in iscsiDevEntries[3]) and
                    (chap_user in iscsiDevEntries[4]) and
                    (chap_pass in iscsiDevEntries[5])
            ):
                return True
        return False

    def __updateISCSI_initiator(self, new_initiator_iqn):
        # test existing iscsi iqn;
        # if same then skip /etc/iscsi/initiatorname.iscsi
        f = open('/etc/iscsi/initiatorname.iscsi', 'r')
        initiatorname_iscsi = f.read()
        f.close()

        found = False
        lines = initiatorname_iscsi.split('\n')
        for line in lines:
            if line.strip().startswith('InitiatorName'):
                tokens = line.split('=')
                if len(tokens) >= 2 and tokens[0].strip() == 'InitiatorName':
                    if tokens[1].strip() == str(new_initiator_iqn).strip():
                        self.log.warning(('__updateISCSI_initiator: ' +
                                          'new and old iqn are the same ' +
                                          '(%s), not updating.')
                                         % str(new_initiator_iqn))
                        return
                    else:
                        index = lines.index(line)
                        self.log.debug('line: %s, lines[%s]: %s'
                                       % (line, str(index),
                                          str(lines[index])))
                        lines[index] = '##' + line
                        lines.insert(
                            index + 1,
                            ('InitiatorName=' + str(new_initiator_iqn) + '\n'))
                        found = True
                        break

        if not found:
            lines.append('InitiatorName=' + str(new_initiator_iqn) + '\n')

        self.log.debug('initiatorname (lines): %s ' % lines)

        # stop open iscsi
        command = 'service'
        paths = ['./', '/sbin/', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Unable to find %s utility ' +
                            'in the following paths: %s')
                           % (command, str(paths)))
            self.log.error('Unable to run service %s'
                           % self.iscsiInitScript)
            return

        try:
            # Stop iSCSI

            cmd = [executable, self.iscsiInitScript, 'stop']
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error(('rtncode: %s - ' +
                                'Failed to shutdown open-iscsi ' +
                                'with command: %s')
                               % (str(rtncode), str(cmd)))
                return None
        except Exception as e:
            self.log.exception('Failed to shutdown open-iscsi with command: ' +
                               str(cmd))
            self.log.error('Exception was of type: %s' % (str(type(e))))
            return

        # update initiator file
        f = open('/etc/iscsi/initiatorname.iscsi', 'w')
        for line in lines:
            f.write(line + '\n')
        f.close()

        try:
            # Start iSCSI
            cmd = [executable, self.iscsiInitScript, 'start']
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error(('rtncode: %s - ' +
                                'Failed to start open-iscsi ' +
                                'with command: %s')
                               % (str(rtncode), str(cmd)))
                return None
        except Exception as e:
            self.log.exception('Failed to start open-iscsi with command: ' +
                               str(cmd))
            self.log.error('Exception was of type: %s' % (str(type(e))))
            return

        # clean up files from previous mounts, rm /var/run/neuca/storage/*
        for f in os.listdir(self.storage_dir):
            self.log.debug('Removing file: %s' % f)
            os.remove(self.storage_dir + f)

    def __ISCSI_discover(self, ip, port):
        self.log.debug('__ISCSI_discover(self, %s)' % ip)
        command = 'iscsiadm'
        paths = ['./', '/bin', '/usr/bin', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return None

        try:
            # discover targets:
            # iscsiadm --mode discovery
            # --type sendtargets --portal 172.16.101.43
            cmd = [
                executable,
                '--mode', 'discovery', '--type',
                'sendtargets', '--portal',
                ip
            ]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error(('rtncode: %s - ' +
                                'Failed to discover iSCSI targets ' +
                                'with command: %s')
                               % (str(rtncode), str(cmd)))
                return None

            self.log.debug('Targets:\n' + str(data_stdout).rstrip('\n'))
        except Exception as e:
            self.log.exception('Failed to discover iSCSI targets ' +
                               'for device with command: ' + str(cmd))
            self.log.error('Exception was of type: %s' % (str(type(e))))
            return None

        targets = []
        lines = data_stdout.split('\n')
        for line in lines:
            if line.strip().startswith(ip):
                line_split = line.split()
                self.log.debug('line_split: ' + str(line_split))
                if (
                        len(line_split) >= 2 and
                        line_split[0].startswith(ip + ':' + port)
                ):
                    targets.append(line_split[1].strip())
                    self.log.debug('Adding target: ' +
                                   str(line_split[1].strip()))

        self.log.debug('Return targets: ' + str(targets))
        return targets

    def __updateISCSI_attach(self, device, target, ip, port, chap_user,
                             chap_pass):
        self.log.debug('__updateISCSI_target_login(self, %s, %s, %s, %s)'
                       % (device, target, ip, port))
        command = 'iscsiadm'
        paths = ['./', '/bin', '/usr/bin', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return

        # Attach the device is it is not already attached
        if not os.path.exists(device):
            # iSCSI device not attached
            # set authmethod:
            # iscsiadm --mode node --targetname target0
            # --portal 172.16.101.43:3260 --op=update
            # --name node.session.auth.authmethod --value=CHAP
            try:
                cmd = [
                    executable,
                    '--mode', 'node', '--targetname',
                    target,
                    '--portal',
                    (ip + ':' + port),
                    '--op=update', '--name',
                    'node.session.auth.authmethod', '--value=CHAP'
                ]
                rtncode, data_stdout, data_stderr = Commands.run(
                    cmd, timeout=60)
                if rtncode != 0:
                    self.log.error(('rtncode: %s - ' +
                                    'Failed to set iSCSI authmethod for ' +
                                    'device (%s) with command: %s')
                                   % (str(rtncode), device, str(cmd)))
                    return
            except Exception as e:
                self.log.exception(('Failed to set iSCSI authmethod for ' +
                                    'device (%s) with command: %s')
                                   % (device, str(cmd)))
                self.log.error('Exception was of type: %s' % (str(type(e))))
                return

            # set chap username:
            # iscsiadm --mode node --targetname target0
            # --portal 172.16.101.43:3260 --op=update
            # --name node.session.auth.username --value=username
            try:
                cmd = [
                    executable,
                    '--mode', 'node', '--targetname',
                    target,
                    '--portal',
                    (ip + ':' + port),
                    '--op=update', '--name',
                    'node.session.auth.username',
                    ('--value=' + chap_user)
                ]
                rtncode, data_stdout, data_stderr = Commands.run(
                    cmd, timeout=60)
                if rtncode != 0:
                    self.log.error(('rtncode: %s - ' +
                                    'Failed to set iSCSI chap user for ' +
                                    'device (%s) with command: %s')
                                   % (str(rtncode), device, str(cmd)))
                    return
            except Exception as e:
                self.log.exception(('Failed to set iSCSI chap user for ' +
                                    'device (%s) with command: %s')
                                   % (device, str(cmd)))
                self.log.error('Exception was of type: %s' % (str(type(e))))
                return

            # set chap password:
            # iscsiadm --mode node --targetname target0
            # --portal 172.16.101.43:3260 --op=update
            # --name node.session.auth.password --value=password
            try:
                cmd = [
                    executable,
                    '--mode', 'node', '--targetname',
                    target,
                    '--portal',
                    (ip + ':' + port),
                    '--op=update', '--name',
                    'node.session.auth.password',
                    ('--value=' + chap_pass)
                ]
                rtncode, data_stdout, data_stderr = Commands.run(
                    cmd, timeout=60)
                if rtncode != 0:
                    self.log.error(('rtncode: %s - ' +
                                    'Failed to set iSCSI chap password for ' +
                                    'device (%s) with command: %s')
                                   % (str(rtncode), device, str(cmd)))
                    return
            except Exception as e:
                self.log.exception(('Failed to set iSCSI chap password for ' +
                                    'device (%s) with command: %s')
                                   % (device, str(cmd)))
                self.log.error('Exception was of type: %s' % (str(type(e))))
                return

            # attach target:
            # iscsiadm --mode node --targetname target0
            # --portal 172.16.101.43:3260 --login
            try:
                cmd = [
                    executable,
                    '--mode', 'node', '--targetname',
                    target,
                    '--portal',
                    (ip + ':' + port),
                    '--login'
                ]
                rtncode, data_stdout, data_stderr = Commands.run(
                    cmd, timeout=60)
                if rtncode != 0:
                    self.log.warning(('rtncode: %s - ' +
                                      'Failed to attach iSCSI target for ' +
                                      'device (%s) with command: %s')
                                     % (str(rtncode), device, str(cmd)))
                    self.__updateISCSI_target_rescan(device, target, ip, port)
                else:
                    self.log.debug('Attach stdout: ' + str(data_stdout))
            except Exception as e:
                self.log.exception(('Failed to attach iSCSI target for ' +
                                    'device (%s) with command: %s')
                                   % (device, str(cmd)))
                self.log.error('Exception was of type: %s' % (str(type(e))))
                self.__updateISCSI_target_rescan(device, target, ip, port)
        else:
            self.log.debug('Device already connected: ' + device)
            return

        self.log.debug('Checking device attached: ' + device)
        count = 0
        while not os.path.exists(device):
            if count >= 10:
                break
            self.log.debug('Device not attached: (%s), attempt %s'
                           % (device, str(count)))
            count = count + 1
            time.sleep(1)

    def __updateISCSI_target_rescan(self, device, target, ip, port):
        self.log.debug('__updateISCSI_target_rescan(self, %s, %s)'
                       % (device, str(target)))
        command = 'iscsiadm'
        paths = ['./', '/bin', '/usr/bin', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return

        # iscsiadm -m discovery -t st -p 10.104.0.2 -o delete -o new
        try:
            cmd = [
                executable,
                '-m', 'discovery', '-t', 'st', '--portal',
                (ip + ':' + port),
                '-o', 'delete', '-o', 'new'
            ]
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error(('rtncode: %s - ' +
                                'Failed re-discovery with command: %s')
                               % (str(rtncode), str(cmd)))
                return
        except Exception as e:
            self.log.exception('Failed re-discovery with command: %s'
                               % str(cmd))
            self.log.error('Exception was of type: %s' % (str(type(e))))
            return

        # iscsiadm -m session --rescan
        try:
            cmd = [executable, '--mode', 'session', '--rescan']
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=60)
            if rtncode != 0:
                self.log.error(('rtncode: %s - ' +
                                'Failed to re-scan with command: ')
                               % (str(rtncode), str(cmd)))
                return
        except Exception as e:
            self.log.exception('Failed to re-scan with command: %s'
                               % str(cmd))
            self.log.error('Exception was of type: %s' % (str(type(e))))
            return

        self.log.debug('Checking device attached: ' + device)
        count = 0
        while not os.path.exists(device):
            self.log.debug('Device not attached: (%s), attempt %s'
                           % (device, str(count)))
            count = count + 1
            if count > 10:
                break
            time.sleep(1)

    def __updateISCSI_format(self, device, fs_type, fs_options):
        self.log.debug('__updateISCSI_format(self, %s, %s, %s)'
                       % (device, str(fs_type), str(fs_options)))
        command = 'mkfs'
        paths = ['./', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return

        if os.path.exists(device):
            try:

                cmd = [executable, '-t', fs_type]
                for option in re.split('\s+', fs_options):
                    cmd.append(option)
                cmd.append(device)

                self.log.info('Formatting iSCSI device %s with command: %s'
                              % (device, str(cmd)))

                rtncode, data_stdout, data_stderr = Commands.run(
                    cmd, timeout=3600)
                if rtncode != 0:
                    self.log.error(('rtncode: %s - ' +
                                    'Failed to format iSCSI targets for ' +
                                    'device (%s) with command: %s')
                                   % (str(rtncode), device, str(cmd)))
                    self.log.error('stdout: ' + str(data_stdout))
                    self.log.error('stderr: ' + str(data_stderr))
                    return
            except Exception as e:
                self.log.exception(('Failed to format iSCSI targets for ' +
                                    'device (%s) with command: %s')
                                   % (device, str(cmd)))
                self.log.error('Exception was of type: %s' % (str(type(e))))
        else:
            self.log.debug('iSCSI device not attached: ' + device)

    def __updateISCSI_mount(self, device, fs_type, mount_point):
        self.log.debug('__updateISCSI_mount(self, %s, %s, %s)'
                       % (device, fs_type, mount_point))
        command = 'mount'
        paths = ['./', '/bin/', '/usr/bin', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return

        # Mount the file system
        if not os.path.exists(device):
            self.log.debug(('Failed to mount because ' +
                            'iSCSI device (%s) is not attached.')
                           % device)
            return

        self.log.debug('Checking dir: ' + mount_point)
        try:
            os.makedirs(mount_point)
            self.log.debug('Created ' + mount_point)
        except OSError:
            self.log.debug('Mount point exists: ' + mount_point)

        mtab = '/proc/mounts'
        fd = None
        try:
            fd = open(mtab, 'r')
        except Exception:
            self.log.error('Unable to open %s for reading!' % mtab)
            return

        fd.seek(0)
        mtabEntries = list(fd)
        fd.close()
        for entry in mtabEntries:
            if mount_point in entry:
                self.log.error('%s already has a filesystem mounted on it.'
                               % mount_point)
                self.log.error('Aborting attempt to mount %s on %s'
                               % (device, mount_point))
                return

        try:
            cmd = [
                executable,
                '-t', fs_type,
                device, mount_point
            ]

            self.log.info('Mounting iSCSI device %s at %s with command: %s'
                          % (device, mount_point, str(cmd)))
            rtncode, data_stdout, data_stderr = Commands.run(cmd, timeout=3600)
            if rtncode != 0:
                self.log.error(('rtncode: %s - ' +
                                'Failed to mount iSCSI targets for ' +
                                'device (%s) with command: %s')
                               % (str(rtncode), device, str(cmd)))
                self.log.error('stdout: ' + str(data_stdout))
                self.log.error('stderr: ' + str(data_stderr))
                return
        except Exception as e:
            self.log.exception(('Failed to mount iSCSI targets for ' +
                                'device (%s) with command: %s')
                               % (device, str(cmd)))
            self.log.error('Exception was of type: %s' % (str(type(e))))

    def __updateRouter(self, isRtr):
        if isRtr == 'user':
            self.log.info('Router: user controlled')
            return

        f = open('/proc/sys/net/ipv4/ip_forward', 'w')
        if isRtr == 'true':
            self.log.info('Router Yes')
            f.write('1')
        elif isRtr == 'false':
            self.log.info('Router No')
            f.write('0')
        else:
            self.log.info('Unknown Router value: ' + str(isRtr))
        f.close()

    def __addRoute(self, network, router):
        command = 'ip'
        paths = ['./', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return

        cmd = [
            executable,
            'route', 'add',
            network,
            'via',
            router
        ]
        self.log.info('Attempting to add route to %s via %s'
                      % (network, router))
        rtncode = subprocess.call(cmd)
        if rtncode != 0:
            self.log.warning('Unable to add route to %s via %s'
                             % (network, router))

    def __delRoute(self, network):
        command = 'ip'
        paths = ['./', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return

        cmd = [
            executable,
            'route', 'del',
            network
        ]
        self.log.info('Attempting to delete route to %s'
                      % network)
        rtncode = subprocess.call(cmd)
        if rtncode != 0:
            self.log.warning('Unable to delete route to %s'
                             % network)

    def __updateRoute(self, network, router):
        try:
            IPNetwork(network)
        except:
            self.log.error('NEuca: network not in cidr (%s)' % str(network))

        if router == 'down':
            self.log.info('Route down: %s %s' % (str(network), str(router)))
            self.__delRoute(network)
        elif router == 'user':
            pass
        else:
            try:
                IPAddress(router)
            except:
                self.log.error(('NEuca: router not in valid format (%s)' +
                                'or invalid state.') % str(router))
                return
            self.log.info('Route up: %s %s' % (str(network), str(router)))
            self.__delRoute(network)
            self.__addRoute(network, router)

    def __rescanPCI(self):
        try:
            fd = open('/sys/bus/pci/rescan', 'w')
            fd.write('1')
            fd.close()
        except:
            self.log.error('failed to rescan PCI bus')

    def __updateUdevFile(self, mac, systemIfaceName,
                         ifaceConfigString, priority,
                         requestedName=None):
        """
        Updates udev persistent naming files for network interfaces, as
        necessary.

        Returns True if the udev file was modified, and False otherwise.
        """
        # requestedName parameter will be used when we pass user-requested
        # interface names through via user data.

        neucaStr = ('### NEuca generated udev persistent naming file - ' +
                    'MANUAL UPDATES MAY BE OVERWRITTEN.\n')

        udevFile = ('%s/%d-%s-%s.rules'
                    % (self.udevDirectory, priority,
                       self.udevSubstring, mac))
        fd = None
        try:
            fd = open(udevFile, 'a+')
        except Exception:
            self.log.error('Unable to open %s for modifications!' % udevFile)
            return False

        fd.seek(0)
        udevEntries = list(fd)
        modified = False

        neucaHeaderStart = None
        try:
            neucaHeaderStart = udevEntries.index(neucaStr)
        except ValueError:
            pass

        macIter = iter(mac)
        macStr = ':'.join(a + b for a, b in zip(macIter, macIter))
        configCommentStr = '### Config: ' + ifaceConfigString + '\n'
        udevNameEntry = (('SUBSYSTEM=="net", ACTION=="add", ' +
                          'ATTR{address}=="%s", NAME="%s"\n')
                         % (macStr, systemIfaceName))
        udevAuxEntry = ('ATTR{address}=="%s", ENV{NM_UNMANAGED}="1"\n'
                        % macStr)
        if (
                (neucaHeaderStart is None) or
                (udevEntries[neucaHeaderStart + 1] != configCommentStr)
        ):
            udevEntries = []
            udevEntries.append(neucaStr)
            udevEntries.append(configCommentStr)
            udevEntries.append(udevNameEntry)
            if priority == self.udevDataPrio:
                udevEntries.append(udevAuxEntry)
            modified = True

        if modified:
            try:
                fd.seek(0)
                fd.truncate()
                for line in udevEntries:
                    fd.write(line)
            except Exception:
                self.log.error('Error writing modifications to: ' +
                               udevFile)
                modified = False

        fd.close()
        return modified

    def __cleanStaleUdevFiles(self, interfaceList):
        """
        Cleans up stale udev files, but only if the instance data
        has been fetched within the last 15 seconds (i.e. it's
        "fresh").
        """
        dpCheckTime = time.time()
        if ((dpCheckTime - self.instanceData.fetchTime) < 15):
            dpUdevs = glob.glob(('%s/%d-%s*.rules'
                                 % (self.udevDirectory,
                                    self.udevDataPrio,
                                    self.udevSubstring)))
            freshUdevs = {}
            staleUdevs = []
            for iface in interfaceList:
                mac = iface[0]
                udevFile = ('%s/%d-%s-%s.rules'
                            % (self.udevDirectory,
                               self.udevDataPrio,
                               self.udevSubstring,
                               mac))
                freshUdevs[udevFile] = True

            for u in dpUdevs:
                e = freshUdevs.get(u)
                if e is None:
                    staleUdevs.append(u)

            for u in staleUdevs:
                try:
                    os.remove(u)
                    self.log.debug('Removed stale udev file: %s'
                                   % u)
                except Exception as e:
                    self.log.exception('Could not delete udev file %s' % u)
                    self.log.error('Exception was of type: %s'
                                   % (str(type(e))))

    def __disableNetworkManager(self, systemIfaceName):
        """
        Disable NetworkManager management for the interface in question,
        if NetworkManager is found to be present.
        Sadly, just setting NM_UNMANAGED from udev is insufficient.
        """
        command = 'nmcli'
        paths = ['./', '/bin', '/usr/bin', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.debug(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            self.log.debug(('NetworkManager is probably not installed; ' +
                            'lucky you!'))
            return

        # Set the interface as unmanaged.
        cmd = [
            executable,
            'device', 'set',
            systemIfaceName,
            'managed', 'no'
        ]
        self.log.info('Attempting to mark %s as unmanaged for NetworkManager'
                      % systemIfaceName)
        rtncode = subprocess.call(cmd)
        if rtncode == 0:
            self.log.debug('Interface %s successfully marked as unmanaged.'
                           % systemIfaceName)
        else:
            self.log.warning(('Interface %s could not be marked unmanaged ' +
                              'in NetworkManager. Unexpected behavior ' +
                              'is likely.'))
            return

    def __triggerUdev(self):
        """
        Force udev to re-scan any new udev files that may have been created,
        then force a trigger of udev to process any newly defined rules (in
        this case, only for network interfaces).
        """
        command = 'udevadm'
        paths = ['./', '/sbin', '/usr/sbin']

        executable = self.__findCommandInPaths(command, paths)
        if executable is None:
            self.log.error(('Executable %s does not exist ' +
                            'in paths: %s')
                           % (command, str(paths)))
            return

        # First, force the re-scan.
        cmd = [
            executable,
            'control', '--reload-rules'
        ]
        self.log.info('Attempting to reload udev rules.')
        rtncode = subprocess.call(cmd)
        if rtncode == 0:
            self.log.debug('Rule reload request succeeded.')
        else:
            self.log.warning('Request of udev rule reload failed!')
            return

        # Now, trigger the re-process of newly defined rules.
        cmd = [
            executable,
            'trigger', '--attr-match=subsystem=net'
        ]
        self.log.info('Re-triggering net device rule processing for udev')
        rtncode = subprocess.call(cmd)
        if rtncode == 0:
            self.log.debug('Rule re-trigger request succeeded.')
        else:
            self.log.warning('Request of udev rule re-trigger failed!')
            return

    def __updateHostsFile(self, loopbackAddress, hostName):
        """
        Maintains the loopback entries added to /etc/hosts for novice users.
        """
        neucaStr = ('NEuca loopback modifications - ' +
                    'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        startStr = '### BEGIN ' + neucaStr
        endStr = '### END ' + neucaStr

        fd = None
        try:
            fd = open(self.hostsFile, 'a+')
        except:
            self.log.error('Unable to open ' + self.hostsFile +
                           ' for modifications!')
            return

        fd.seek(0)
        hostsEntries = list(fd)
        modified = False

        neucaEntry = None
        try:
            neucaEntry = hostsEntries.index(startStr)
        except ValueError:
            pass

        newHostsEntry = loopbackAddress + '\t' + hostName + '\n'
        if neucaEntry is not None:
            if (hostsEntries[neucaEntry + 1] != newHostsEntry):
                hostsEntries[neucaEntry + 1] = newHostsEntry
                modified = True
        else:
            hostsEntries.append('\n')
            hostsEntries.append(startStr)
            hostsEntries.append(newHostsEntry)
            hostsEntries.append(endStr)
            hostsEntries.append('\n')
            modified = True

        if modified:
            try:
                fd.seek(0)
                fd.truncate()
                for line in hostsEntries:
                    fd.write(line)
            except:
                self.log.error('Error writing modifications to ' +
                               self.hostsFile)
        fd.close()

    def updateNetworking(self):
        """
        Add/remove network interfaces using the iproute2 tools.
        """
        super(NEucaLinuxCustomizer, self).updateNetworking()

        self.__rescanPCI()

        # Fetch the list of dataplane interfaces.
        interfaces = self.instanceData.getAllInterfaces()
        systemIfaces = self.__getPhysicalIfacesByMac()
        for iface in interfaces:
            mac = iface[0]
            config = iface[1].split(':')
            state = config[0]

            # Get the system name for the dataplane interface from
            # the system interface hash, then remove it from the
            # hash and update the udev file.
            sysName = systemIfaces.get(mac)
            updateIface = False
            if sysName:
                del systemIfaces[mac]
                updateIface = self.__updateUdevFile(mac, sysName, config,
                                                    self.udevDataPrio)

            if updateIface or self.firstRun:
                # Make sure that any newly generated udev files are processed.
                self.__triggerUdev()
                # Make sure that NetworkManager sods off, for any
                # dataplane interfaces.
                self.__disableNetworkManager(sysName)
                # address_type is currently unused, but will be in future.
                try:
                   # address_type = config[1]
                   cidr = config[2]
                except:
                   # address_type = None
                   cidr = None
                self.__updateInterface(mac, state, cidr)
            else:
                self.log.debug(('Not updating interface for MAC %s ' +
                                'at this time.')
                               % mac)

        # There *should* only be one remaining interface in systemIfaces -
        # the management interface.
        # If more than one remaining interface? Pass.
        if (len(systemIfaces) == 1):
            for mac, sysName in systemIfaces.iteritems():
                self.__updateUdevFile(mac, sysName, "management",
                                      self.udevMgmtPrio)
        else:
            self.log.debug('Unexpected number of interfaces ' +
                           'in systemIfaces; skipping udev file update ' +
                           'for management interface.')

        # Clean up from any dataplane interfaces that may have been
        # removed.
        self.__cleanStaleUdevFiles(interfaces)

        # update routes
        self.__updateRouter(self.isRouter())
        routes = self.getAllRoutes()
        for route in routes:
            self.__updateRoute(route[0], route[1])

    def runNewScripts(self):
        scripts = self.instanceData.getAllScripts()
        for s in scripts:
            script = NeucaScript(s[0], s[1])
            script.run()

    def updateStorage(self):
        iscsi_iqn = self.getISCSI_iqn()

        if iscsi_iqn is None:
            self.log.info('No iSCSI IQN specified. ' +
                          'Skipping storage configuration.')
            return
        self.log.debug('iscsi_iqn = ' + str(iscsi_iqn))

        self.__updateISCSI_initiator(iscsi_iqn)

        storage_list = self.instanceData.getAllStorage()
        for device in storage_list:
            dev_name = device[0]
            dev_fields = dict(enumerate(device[1].split(':')))

            proto = dev_fields.get(0)
            if proto == 'iscsi':
                try:
                    ip = dev_fields.get(1)
                    port = dev_fields.get(2)
                    lun = dev_fields.get(3)
                    chap_user = dev_fields.get(4)
                    chap_pass = dev_fields.get(5)
                    shouldAttach = dev_fields.get(6)

                    # The following fields may not exist.
                    # Since we are doing a get() on a dict, however,
                    # they'll default to None if non-existent.
                    fs_type = dev_fields.get(7)
                    fs_options = dev_fields.get(8)
                    fs_shouldFormat = dev_fields.get(9)
                    mount_point = dev_fields.get(10)

                    if (
                            self.__checkISCSI_handled(dev_name, ip, port, lun,
                                                      chap_user, chap_pass) and
                            not self.firstRun
                    ):
                        self.log.debug(('Skipping previously handled ' +
                                        'storage device: %s')
                                       % dev_name)
                        continue

                    targets = self.__ISCSI_discover(ip, port)
                    if not targets or len(targets) < 1:
                        # Hrm. No targets. Log it, and loop to next item.
                        self.log.error(('Failed to discover iSCSI targets ' +
                                        'for device %s at (%s:%s)')
                                       % (dev_name, ip, port))
                        continue

                    self.log.debug('Found iSCSI targets for %s at (%s:%s)'
                                   % (dev_name, ip, port))
                    self.log.debug('Targets: %s' % str(targets))

                    target = ''
                    dev_path = ''
                    if shouldAttach.lower() == 'yes':
                        self.log.debug(('Attempting to attach LUN %s for %s ' +
                                        'using the following parameters:')
                                       % (lun, dev_name))
                        self.log.debug(('chap_user = %s chap_pass = %s ' +
                                        'fs_type = %s fsoptions = %s ' +
                                        'fs_shouldFormat = %s ' +
                                        'mount_point = %s')
                                       %
                                       (chap_user, chap_pass,
                                        fs_type, fs_options,
                                        fs_shouldFormat,
                                        mount_point))

                        for target in targets:
                            dev_path = (
                                '/dev/disk/by-path/ip-%s:%s-iscsi-%s-lun-%s'
                                % (ip, port, target, lun)
                                )
                            self.log.debug('dev_path = ' + dev_path)

                            # First, if the LUN has not been
                            # attached, attempt to attach it
                            if not os.path.exists(dev_path):
                                self.__updateISCSI_attach(
                                    dev_path, target,
                                    ip, port,
                                    chap_user, chap_pass)

                            # Now, check again to see if the LUN
                            # attached. Attachment *can* transiently
                            # fail, for any number of reasons, so we
                            # allow the top-level loop to re-try
                            # later.
                            if not os.path.exists(dev_path):
                                continue

                            # We need to check __checkISCSI_handled
                            # again, because we don't want to
                            # accidentally re-format a device, after
                            # restarting neuca.
                            if (
                                    fs_shouldFormat.lower() == 'yes'
                                    and
                                    not self.__checkISCSI_handled(dev_name,
                                                                  ip, port,
                                                                  lun,
                                                                  chap_user,
                                                                  chap_pass)
                                    and
                                    self.__checkISCSI_shouldFormat(
                                        dev_path, fs_type)
                            ):
                                self.log.debug('Formatting FS')
                                self.__updateISCSI_format(
                                    dev_path, fs_type, fs_options)
                                pass
                            if mount_point:
                                self.log.debug('Mounting FS')
                                self.__updateISCSI_mount(
                                    dev_path, fs_type, mount_point)
                                pass
                            break

                        if not os.path.exists(dev_path):
                            self.log.error(('iSCSI storage failed. ' +
                                            'Device %s not attached. ' +
                                            'Retry next loop.')
                                           % dev_name)
                            continue
                    else:
                        self.log.debug('Not attaching LUN for %s'
                                       % dev_name)

                    # mark storage device handled
                    if not os.path.exists(self.storage_dir):
                        os.makedirs(self.storage_dir)

                    storage_params = [
                        ('ip', ip),
                        ('port', port),
                        ('target', target),
                        ('lun', lun),
                        ('chap_user', chap_user),
                        ('chap_pass', chap_pass),
                        ('shouldAttach', shouldAttach),
                        ('fs_type', fs_type),
                        ('fs_options', fs_options),
                        ('fs_shouldFormat', fs_shouldFormat),
                        ('mount_point', mount_point)
                    ]
                    fd = open(self.storage_dir + '/' + dev_name, 'w')
                    for name, value in storage_params:
                        fd.write(name + ' = ' + value + '\n')
                    fd.close()

                except Exception as e:
                    self.log.exception('Failure while handling iSCSI storage.')
                    self.log.error('Exception was of type: %s'
                                   % (str(type(e))))
            else:
                self.log.error('Unknown storage protocol: %s' % proto)

    def updateHostname(self):
        self.log.debug('updateHostname')

        # get the new hostname
        new_hostname = self.instanceData.getHostname()
        if new_hostname is None:
            self.log.error('host_name undefined; not setting.')
            return

        # get the old hostname
        try:
            old_hostname = socket.gethostname()
        except:
            old_hostname = None

        self.log.debug('new_hostname = %s, old_hostname = %s'
                       % (str(new_hostname), str(old_hostname)))
        if new_hostname != old_hostname:
            cmd = [
                '/bin/hostname',
                str(new_hostname)
            ]
            rtncode = subprocess.call(cmd)
            if rtncode == 0:
                self.log.debug('Hostname changed to: %s'
                               % str(new_hostname))
            else:
                self.log.error('Failed to set hostname.')
                return

        set_loopback = True
        try:
            set_loopback = CONFIG.getboolean('runtime',
                                             'set-loopback-hostname')
        except Exception:
            # Somebody had to have tried setting something other
            # than the default, but got it wrong. Go with the default.
            pass

        if set_loopback:
            loopback_address = CONFIG.get('runtime', 'loopback-address')
            if (all_matching_cidrs(loopback_address, [loopbackNet])):
                self.__updateHostsFile(loopback_address, new_hostname)
            else:
                self.log.warn(
                    'Specified address not in loopback range; ' +
                    'address specified was: '
                    + loopback_address)

    def buildIgnoredMacSet(self):
        mac_string = CONFIG.get('runtime', 'dataplane-macs-to-ignore')
        mac_string = mac_string.replace(' ', '')
        mac_list = mac_string.split(',')
        for mac in mac_list:
            if mac:
                mac_cleaned = mac.lower().replace(':', '')
                self.ignoredMacSet.add(mac_cleaned)
                self.log.debug('Added MAC %s to ignored list.' % mac)


class NEucaRedhatCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        import platform
        distro_version = int(platform.dist()[1].split('.')[0])
        if (((distro == 'fedora') and (distro_version >= 15))
                or (((distro == 'redhat') or (distro == 'centos')) and
                    (distro_version >= 7))):
            super(NEucaRedhatCustomizer, self).__init__(distro, 'iscsid')
        else:
            super(NEucaRedhatCustomizer, self).__init__(distro, 'iscsi')


class NEucaDebianCustomizer(NEucaLinuxCustomizer):
    def __init__(self, distro):
        import platform
        distro_version = int(platform.dist()[1].split('.')[0])
        if ((distro == 'Ubuntu') and (distro_version >= 16)):
            super(NEucaDebianCustomizer, self).__init__(distro, 'iscsid')
        else:
            super(NEucaDebianCustomizer, self).__init__(distro, 'open-iscsi')
