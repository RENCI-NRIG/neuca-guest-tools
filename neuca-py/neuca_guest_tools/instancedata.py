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
        self.interfaces = None
        self.users = None
        self.storage = None
        self.scripts = None
        self.routes = None
        
        try:
            self.__testing__ = CONFIG.getboolean('runtime', 'testing')
        except Exception:
            self.__testing__ = False

    def __get_testing_userdata():
        f = open((neuca_ConfDir + '/' + 'testing_userdata.ini'), 'r')
        rtnStr = f.read()
        f.close()
        return rtnStr

    def updateInterfacesFromComet(self):
        interfaces=self.getCometData('interfaces')
        if interfaces is not None:
            result = []
            for i in interfaces:
                mac=str(i["mac"])
                value=str(i["state"])
                value+=":"
                value+=str(i["ipVersion"])
                value+=":"
                if i.get("ip") :
                    value+=str(i["ip"])
                tup=mac,value
                result.append(tup)
            return result
        return None

    def updateScriptsFromComet(self):
        scripts = self.getCometData('scripts')
        if scripts is not None :
            result = []
            for s in scripts:
                scriptName=str(s["scriptName"])
                scriptBody=str(s["scriptBody"])
                tup=scriptName,scriptBody
                result.append(tup)
            return result
        return None

    def updateRoutesFromComet(self):
        routes = self.getCometData('routes')
        if routes is not None :
            result = []
            for r in routes:
                routeNetwork=str(r["routeNetwork"])
                routeNextHop=str(r["routeNextHop"])
                tup = routeNetwork, routeNextHop
                result.append(tup)
            return result
        return None

    def updateStorageFromComet(self):
        storage = self.getCometData('storage')
        if storage is not None:
            result = []
            for s in storage :
                device=str(s["device"])
                config=str(s["storageType"]) 
                config+=":" 
                config+=str(s["targetIp"]) 
                config+=":" 
                config+=str(s["targetPort"]) 
                config+=":" 
                config+=str(s["targetLun"]) 
                config+=":" 
                config+=str(s["targetChapUser"]) 
                config+=":" 
                config+=str(s["targetChapSecret"])
                config+=":" 
                config+=str(s["targetShouldAttach"])
                config+=":" 
                config+=str(s["fsType"])
                config+=":" 
                config+=str(s["fsOptions"]) 
                config+=":" 
                config+=str(s["fsShouldFormat"]) 
                config+=":" 
                config+=str(s["fsMountPoint"])
                tup = device, config
                result.append(tup)
            return result
        return None

    def updateUsersFromComet(self):
        users = self.getCometData('users')
        if users is not None :
            result = []
            for u in users :
                login=str(u["user"])
                sudokeys=str(u["sudo"]) + ":" + str(u["key"])
                tup = login, sudokeys
                result.append(tup)
            return result
        return None

    def updateCometData(self):
        self.interfaces = self.updateInterfacesFromComet()
        self.scripts = self.updateScriptsFromComet()
        self.routes = self.updateRoutesFromComet()
        self.users = self.updateUsersFromComet()
        self.storage = self.updateStorageFromComet()

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

        if self.getCometHost() is not None :
            self.updateCometData()

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
        secData = None
        if section == 'interfaces' :
            secData = self.interfaces
        elif section == 'users' :
            secData = self.users
        elif section == 'scripts' :
            secData = self.scripts
        elif section == 'routes' :
            secData = self.routes
        elif section == 'storage' :
            secData = self.storage
        if secData is not None:
            for s in secData:
                if s[0] == field :
                    return s[1]
        return None

    def getCometData(self, section):
        sliceId = self.getUserDataField("global", "slice_id")
        rId = self.getUserDataField("global", "reservation_id")
        readToken = self.getUserDataField("global", "cometreadtoken")
        if sliceId is not None and rId is not None and readToken is not None:
            comet = CometInterface(self.getCometHost(), None, None, None)
            resp = comet.get_family(sliceId, rId, readToken, section)
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
                    return secData
            else:
                return None
        else :
            print("sliceId/rId/readToken could not be determined")
            return None

    def getBootScript(self):
        return self.getUserDataField('scripts', 'bootscript')

    def getAllScripts(self):
        if self.getCometHost() is not None :
            return self.scripts 
        else :
            return self.config.items('scripts')

    def getInterface(self, iface):
        return self.getUserDataField('interfaces', iface)

    def getAllInterfaces(self):
        if self.getCometHost() is not None :
            return self.interfaces
        else :
            return self.config.items('interfaces')

    def getAllUsers(self):
        if self.getCometHost() is not None :
            return self.users
        else :
            return self.config.items('users')

    def getAllStorage(self):
        if self.getCometHost() is not None :
            return self.storage
        else :
            return self.config.items('storage')

    def getAllRoutes(self):
        if self.getCometHost() is not None :
            return self.storage 
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
        try:
            return self.config.get("global", "comethost")
        except Exception:
            return None
