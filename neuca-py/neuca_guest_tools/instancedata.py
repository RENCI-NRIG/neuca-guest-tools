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

import ConfigParser
import boto.utils

from neuca_guest_tools import CONFIG
from neuca_guest_tools import _ConfDir as neuca_ConfDir
from neuca_guest_tools.util import TempFile


class NEucaInstanceData(object):
    def __init__(self):
        self.config = None
        self.publicIP = None
        self.userData = None
        try:
            self.__testing__ = CONFIG.getboolean('runtime', 'testing')
        except Exception:
            self.__testing__ = False

    def __get_testing_userdata():
        f = open((neuca_ConfDir + '/' + 'testing_userdata.ini'), 'r')
        rtnStr = f.read()
        f.close()
        return rtnStr

    def updateInstanceData(self):
        # Local assignments, in order to shorten things.
        get_meta = boto.utils.get_instance_metadata
        get_user = boto.utils.get_instance_userdata

        if self.__testing__:
            self.publicIP = '127.0.0.1'
            self.userData = self.__get_testing_userdata()
        else:
            self.publicIP = str(get_meta()['public-ipv4'])
            self.userData = get_user()

        fh = TempFile(prefix='euca-n-userdata')
        fh.write(self.userData)
        fh.close()

        self.config = ConfigParser.RawConfigParser()
        self.config.read(fh.path)

    def getUserDataField(self, section, field):
        try:
            return self.config.get(section, field)
        except ConfigParser.NoOptionError, ConfigParser.NoSectionError:
            return None

    def getBootScript(self):
        return self.getUserDataField('scripts', 'bootscript')

    def getAllScripts(self):
        return self.config.items('scripts')

    def getInterface(self, iface):
        return self.getUserDataField('interfaces', iface)

    def getAllInterfaces(self):
        return self.config.items('interfaces')

    def getAllStorage(self):
        return self.config.items('storage')

    def getAllRoutes(self):
        return self.config.items('routes')

    def getPublicIP(self):
        return self.publicIP

    def getUserData(self):
        return self.userData

    def getHostname(self):
        hostname = self.getUserDataField('global', 'host_name')
        if hostname:
            hostname = hostname.strip()
        return hostname

    def isRouter(self):
        isRtr = self.getUserDataField('global', 'router')
        if isRtr is None:
            isRtr = 'user'
        else:
            isRtr = isRtr.lower()
        return isRtr

    def getISCSI_iqn(self):
        iqn = self.getUserDataField('global', 'iscsi_initiator_iqn')
        if iqn:
            iqn = iqn.strip()
        return iqn
