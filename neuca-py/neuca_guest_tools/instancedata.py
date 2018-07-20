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
import time
import boto.utils
import json

from neuca_guest_tools import CONFIG
from neuca_guest_tools import _ConfDir as neuca_ConfDir
from neuca_guest_tools.util import TempFile
from comet_common_iface import *


class NEucaInstanceData(object):
    def __init__(self):
        self.config = None
        self.publicIP = None
        self.userData = None
        self.fetchTime = 0
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

        # Finally, record when this instanceData was fetched, so we
        # know how "fresh" it is.
        self.fetchTime = time.time()

    def getUserDataField(self, section, field):
        try:
	    if section == 'global' or self.getCometHost() is None :
                return self.config.get(section, field)
            else :
                return self.getCometDataField(section, field)
        except ConfigParser.NoOptionError, ConfigParser.NoSectionError:
            return None

    def getCometDataField(self, section, field):
        secData = self.getCometData(section)
        if secData is not None :
            secJson = json.loads(secData)
            for s in secJson :
		for value in s.values() :
		  if value == field :
		     return json.dumps(s)
	return None

    def getCometData(self, section):
        sliceId = self.getUserDataField("global", "slice_id")
        unitId = self.getUserDataField("global", "unit_id")
        readToken = self.getUserDataField("global", "cometreadtoken")
        if sliceId is not None and unitId is not None and readToken is not None:
            comet = CometInterface(self.getCometHost(), None, None, None)
            resp = comet.get_family(sliceId, unitId, readToken, section)
            if resp.status_code != 200:
                print ("Failure occured in fetching family from comet" + section)
                return None
            if resp.json()["value"].get("error") :
                print ("Error occured in fetching family from comet" + section + resp.json()["value"]["error"])
		return None
            elif resp.json()["value"] :
                value = resp.json()["value"]["value"]
                if value is not None :
                    secData = json.loads(json.loads(value)["val_"])
                    return json.dumps(secData)
            else:
                return None
        else :
            print("sliceId/unitId/readToken could not be determined")
            return None

    def getBootScript(self):
        if self.getCometHost() is not None :
            scripts = self.getCometData('scripts')
            if scripts is not None :
                scriptsJson = json.loads(scripts)
                for script in scriptsJson :
                   if script["scriptName"] == "bootscript" :
                       return json.dumps(script)
            return None
        else :
            return self.getUserDataField('scripts', 'bootscript')

    def getAllScripts(self):
        if self.getCometHost() is not None :
            return self.getCometData('scripts')
        else :
            return self.config.items('scripts')

    def getInterface(self, iface):
        return self.getUserDataField('interfaces', iface)

    def getAllInterfaces(self):
         if self.getCometHost() is not None :
             return self.getCometData('interfaces')
         else :
             return self.config.items('interfaces')

    def getAllUsers(self):
        if self.getCometHost() is not None :
            return self.getCometData('users')
        else :
            return self.config.items('users')

    def getAllStorage(self):
        if self.getCometHost() is not None :
            return self.getCometData('storage')
        else :
            return self.config.items('storage')

    def getAllRoutes(self):
        if self.getCometHost() is not None :
            return self.getCometData('routes')
        else :
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

    def getCometHost(self):
        return self.config.get("global", "comethost")
