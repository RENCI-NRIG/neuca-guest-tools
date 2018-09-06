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
import subprocess
import logging
import os

from neuca_guest_tools import CONFIG, LOGGER
from neuca_guest_tools import _ConfDir as neuca_ConfDir
from neuca_guest_tools.util import TempFile
from comet_common_iface import *

urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NEucaInstanceData(object):
    def __init__(self, enableChameleon=False):
        self.chameleon = enableChameleon
        self.log = logging.getLogger(LOGGER)
        self.config = None
        self.publicIP = None
        self.userData = None
        self.fetchTime = 0
        self.interfaces = None
        self.users = None
        self.storage = None
        self.scripts = None
        self.routes = None
        self.neucaTmpDir = "/var/neuca"
        self.ccMeta = None

        cmd = [
        "/bin/mkdir", "-p", self.neucaTmpDir
        ]
        FNULL = open(os.devnull, 'w')
        rtncode = subprocess.call(cmd, stdout=FNULL)
        if rtncode != 0 :
            print ("Failed to create neuca directory")
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

    def updateHostsFromComet(self):
        try:
            self.log.debug("Updating hosts locally")
            groups = self.getUserDataField("global", "comethostsgroupread")
            if groups is None or groups == "Not Specified":
                return

            sliceId = self.getUserDataField("global", "slice_id")
            readToken = self.getUserDataField("global", "slicecometreadtoken")
            writeToken = self.getUserDataField("global", "slicecometwritetoken")
            rId = self.getUserDataField("global", "reservation_id")

            if sliceId is None or readToken is None or writeToken is None:
                return

            for g in groups.split(",") :
                section = "hosts" + g
                newHosts = ""
                comet = CometInterface(self.getCometHost(), None, None, None, self.log)
                self.log.debug("Processing section " + section)
                resp = comet.invokeRoundRobinApi('enumerate_families', sliceId, None, readToken, None, section, None)

                if resp.status_code != 200:
                    self.log.error("Failure occured in enumerating family from comet" + section)
                    continue

                if resp.json()["value"] and resp.json()["value"]["entries"]:
                    for e in resp.json()["value"]["entries"]:
                        if e["key"] == rId :
                            continue

                        self.log.debug("processing " + e["key"])
                        hosts = json.loads(json.loads(e["value"])["val_"])
                        for h in hosts:
                            if h["ip"] == "" :
                                continue

                            self.log.debug("check if " + h["hostName"] + " exists")
                            strToWrite = h["ip"] + " " + h["hostName"] + "\n"
                            newHosts = newHosts + strToWrite
                strComment = "#comethosts\n"

                f=open("/etc/hosts", "r")
                lines=f.readlines()
                f.close()
                f=open("/etc/hosts", "w")
                for line in lines :
                    if line != strComment :
                        f.write(line)
                    else:
                        break
                f.write(strComment)
                if newHosts != "" :
                    f.write(newHosts)
                f.close()
        except Exception as e:
            self.log.error('updateHostsFromComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updateHostsFromComet: Exception : %s' % (str(e)))

    def updatePubKeysFromComet(self):
        try:
            self.log.debug("Updating PubKeys locally")
            groups = self.getUserDataField("global", "cometpubkeysgroupread")
            if groups is None or groups == "Not Specified":
                return

            sliceId = self.getUserDataField("global", "slice_id")
            readToken = self.getUserDataField("global", "slicecometreadtoken")
            writeToken = self.getUserDataField("global", "slicecometwritetoken")
            rId = self.getUserDataField("global", "reservation_id")

            if sliceId is None or readToken is None or writeToken is None:
                return
            for g in groups.split(",") :
                section = "pubkeys" + g
                newKeys = ""
                comet = CometInterface(self.getCometHost(), None, None, None, self.log)
                self.log.debug("Processing section " + section)
                resp = comet.invokeRoundRobinApi('enumerate_families', sliceId, None, readToken, None, section, None)
                if resp.status_code != 200:
                    self.log.error("Failure occured in enumerating family from comet" + section)
                    continue
                if resp.json()["value"] and resp.json()["value"]["entries"]:
                    for e in resp.json()["value"]["entries"]:
                        if e["key"] == rId :
                            continue
                        self.log.debug("processing " + e["key"])
                        keys = json.loads(json.loads(e["value"])["val_"])
                        for k in keys:
                            if k["publicKey"] == "" :
                                continue
                            newKeys = newKeys + k["publicKey"]
                strComment = "#cometkeys\n"

                f=open("/root/.ssh/authorized_keys", "r")
                lines=f.readlines()
                f.close()
                f=open("/root/.ssh/authorized_keys", "w")
                for line in lines :
                    if line != strComment :
                        f.write(line)
                    else:
                        break
                f.write(strComment)
                if newKeys != "" :
                    f.write(newKeys)
                f.close()
        except Exception as e:
            self.log.error('updatePubKeysFromComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updatePubKeysFromComet: Exception : %s' % (str(e)))


    def updatePubKeysToComet(self):
        try:
            self.log.debug("Updating PubKeys in comet")
            groups = self.getUserDataField("global", "cometpubkeysgroupwrite")
            if groups is None or groups == "Not Specified":
                return
            sliceId = self.getUserDataField("global", "slice_id")
            rId = self.getUserDataField("global", "reservation_id")
            readToken = self.getUserDataField("global", "slicecometreadtoken")
            writeToken = self.getUserDataField("global", "slicecometwritetoken")
            if sliceId is not None and rId is not None and readToken is not None and writeToken is not None:
                for g in groups.split(",") :
                    checker = None
                    section = "pubkeys" + g
                    comet = CometInterface(self.getCometHost(), None, None, None, self.log)
                    self.log.debug("Processing section " + section)
                    keys = self.getCometData(section, readToken)
                    if keys is None:
                        self.log.debug("empty section " + section)
                        continue
                    for k in keys:
                        if k["publicKey"] == "" :
                            cmd = [
                            "/bin/ssh-keygen", "-t", "rsa", "-N", "", "-f", "/root/.ssh/id_rsa"
                            ]
                            FNULL = open(os.devnull, 'w')
                            rtncode = subprocess.call(cmd, stdout=FNULL)
                            if rtncode == 0:
                                self.log.debug("Keys generated successfully for root user")
                                f = open('/root/.ssh/id_rsa.pub', 'r')
                                keyVal= f.read()
                                f.close()
                                k["publicKey"]=keyVal
                            else:
                                self.log.error("Failed to generate keys for root user")
                            checker = True
                    if checker :
                        val = {}
                        val["val_"] = json.dumps(keys)
                        newVal = json.dumps(val)
                        self.log.debug("Updating " + section + "=" + newVal)
                        resp = comet.invokeRoundRobinApi('update_family', sliceId, rId, readToken, writeToken, section, json.loads(newVal))
                        if resp.status_code != 200:
                            self.log.error("Failure occured in updating pubkeys to comet" + section)
                    else :
                        self.log.debug("Nothing to update")
        except Exception as e:
            self.log.error('updatePubKeysToComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updatePubKeysToComet: Exception : %s' % (str(e)))

    def updateHostsToComet(self):
        try:
            self.log.debug("Updating Hosts in comet")
            groups = self.getUserDataField("global", "comethostsgroupwrite")
            if groups is None or groups == "Not Specified":
                return
            sliceId = self.getUserDataField("global", "slice_id")
            rId = self.getUserDataField("global", "reservation_id")
            readToken = self.getUserDataField("global", "slicecometreadtoken")
            writeToken = self.getUserDataField("global", "slicecometwritetoken")
            hostName = self.getHostname()
            ip = self.getPublicIP()
            if sliceId is not None and rId is not None and readToken is not None and writeToken is not None:
                for g in groups.split(",") :
                    checker = None
                    section = "hosts" + g
                    comet = CometInterface(self.getCometHost(), None, None, None, self.log)
                    self.log.debug("Processing section " + section)
                    hosts = self.getCometData(section, readToken)
                    if hosts is None:
                        self.log.debug("empty section " + section)
                        continue
                    for h in hosts :
                        self.log.debug("Processing host " + h["hostName"])
                        self.log.debug("h[ip]=" + h["ip"] + " ip=" + ip)
                        if h["hostName"] == hostName and h["ip"] != ip :
                            h["ip"] = ip
                            checker = True
                    if checker :
                        val = {}
                        val["val_"] = json.dumps(hosts)
                        newVal = json.dumps(val)
                        self.log.debug("Updating " + section + "=" + newVal)
                        resp = comet.invokeRoundRobinApi('update_family', sliceId, rId, readToken, writeToken, section, json.loads(newVal))
                        if resp.status_code != 200:
                            self.log.debug("Failure occured in updating hosts to comet" + section)
                    else :
                        self.log.debug("Nothing to update")
        except Exception as e:
            self.log.error('updateHostsToComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updateHostsToComet: Exception : %s' % (str(e)))

    def updateCometData(self):
        self.interfaces = self.updateInterfacesFromComet()
        self.scripts = self.updateScriptsFromComet()
        self.routes = self.updateRoutesFromComet()
        self.users = self.updateUsersFromComet()
        self.storage = self.updateStorageFromComet()
        self.updateHostsToComet()
        self.updatePubKeysToComet()
        self.updatePubKeysFromComet()
        self.updateHostsFromComet()

    def updateChameleonInstanceData(self):
        try:
            host="http://169.254.169.254"
            headers = {
                'Accept': 'application/json',
            }
            response = requests.get((host + '/openstack/latest/meta_data.json'), headers=headers, verify=False)
            if response.status_code == 200 :
                self.ccMeta = response.json()
            else :
                self.log.error("Failed to fetch cc meta data")
            response = requests.get((host + '/latest/meta-data/public-ipv4'), headers=headers, verify=False)
            if response.status_code == 200 :
                self.publicIP = response._content
            else :
                self.log.error("Failed to fetch cc public ip")
        except Exception as e:
            self.log.error('updateChameleonInstanceData: Exception : %s' % (str(e)))

    def updateInstanceData(self):
        if self.chameleon :
            self.log.debug("Running on chameleon")
            self.updateChameleonInstanceData()
            self.updateHostsToComet()
            self.updatePubKeysToComet()
            self.updatePubKeysFromComet()
            self.updateHostsFromComet()
            return

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
            if self.chameleon :
                if field == "host_name" :
                    return self.ccMeta["hostname"]
                return self.ccMeta["meta"][field]
            if section == 'global' or self.getCometHost() is None :
                return self.config.get(section, field)
            else :
                return self.getCometDataField(section, field)
        except ConfigParser.NoOptionError, ConfigParser.NoSectionError:
            return None
        except Exception:
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

    def getCometData(self, section, readToken=None):
        sliceId = self.getUserDataField("global", "slice_id")
        rId = self.getUserDataField("global", "reservation_id")
        if readToken is None:
            readToken = self.getUserDataField("global", "cometreadtoken")
        if sliceId is not None and rId is not None and readToken is not None:
            comet = CometInterface(self.getCometHost(), None, None, None, self.log)
            resp = comet.invokeRoundRobinApi('get_family', sliceId, rId, readToken, None, section, None)
            if resp.status_code != 200:
                self.log.error("Failure occured in fetching family from comet" + section)
                return None
            if resp.json()["value"].get("error") :
                self.log.error("Error occured in fetching family from comet" + section + resp.json()["value"]["error"])
                return None
            elif resp.json()["value"] :
                value = resp.json()["value"]["value"]
                if value is not None :
                    secData = json.loads(json.loads(value)["val_"])
                    return secData
            else:
                return None
        else :
            self.log.error("sliceId/rId/readToken could not be determined")
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
            return self.routes
        else :
            return self.config.items('routes')

    def getPublicIP(self):
        return self.publicIP

    def getUserData(self):
        if self.chameleon :
            return json.dumps(self.ccMeta, indent=4)
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
            if self.chameleon :
                return self.ccMeta["meta"]["comethost"]
            return self.config.get("global", "comethost")
        except Exception:
            return None
