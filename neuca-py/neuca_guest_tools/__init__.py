__version__ = '1.7'

import platform
import ConfigParser

_distro = platform.dist()[0]

_ConfDir = '/etc/neuca'
_ConfFile = 'config'

_SetLoopbackHostname = 'true'
_LoopbackAddress = '127.255.255.1'

_StateDir = '/var/lib/neuca'
_StorageDir = _StateDir + '/storage'
_PidDir = '/var/run'
_PidFile = 'neucad.pid'

_LogDir = '/var/log/neuca'
_LogFile = 'neuca-agent.log'
_LogLevel = 'DEBUG'
_LogRetain = '5'
_LogFileSize = '5000000'

_UdevPrefix = 'persistent-neuca'
_DataUdevPriority = '10'
_MgmtUdevPriority = '15'

_CommandTimeout = '300'
_PidFileTimeout = '5'

_IPV4_LOOPBACK_NET = '127.0.0.0/8'
_testing = 'false'

LOGGER = 'neuca_guest_tools_logger'

CONFIG = ConfigParser.SafeConfigParser()
CONFIG.add_section('runtime')
CONFIG.add_section('logging')
CONFIG.add_section('linux')
CONFIG.set('runtime', 'set-loopback-hostname', _SetLoopbackHostname)
CONFIG.set('runtime', 'loopback-address', _LoopbackAddress)
CONFIG.set('runtime', 'dataplane-macs-to-ignore', '')
CONFIG.set('runtime', 'state-directory', _StateDir)
CONFIG.set('runtime', 'pid-directory', _PidDir)
CONFIG.set('runtime', 'pid-file', _PidFile)
CONFIG.set('runtime', 'command-timeout', _CommandTimeout)
CONFIG.set('runtime', 'pidfile-timeout', _PidFileTimeout)
CONFIG.set('runtime', 'testing', _testing)
CONFIG.set('linux', 'udev-prefix', _UdevPrefix)
CONFIG.set('linux', 'data-udev-priority', _DataUdevPriority)
CONFIG.set('linux', 'mgmt-udev-priority', _MgmtUdevPriority)
CONFIG.set('logging', 'log-directory', _LogDir)
CONFIG.set('logging', 'log-file', _LogFile)
CONFIG.set('logging', 'log-level', _LogLevel)
CONFIG.set('logging', 'log-retain', _LogRetain)
CONFIG.set('logging', 'log-file-size', _LogFileSize)
