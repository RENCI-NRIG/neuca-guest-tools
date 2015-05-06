import platform

__version__ = '1.5'
__distro__ = platform.dist()[0]

__ConfDir__ = '/etc/neuca'
__ConfFile__ = 'config'

__SetLoopbackHostname__ = 'true'
__LoopbackAddress__ = '127.255.255.1'

__StateDir__ = '/var/lib/neuca'
__StorageDir__ = __StateDir__ + '/storage'
__PidDir__ = '/var/run'
__PidFile__ = 'neucad.pid'

__LogDir__ = '/var/log/neuca'
__LogFile__ = 'neuca-agent.log'
__LogLevel__ = 'DEBUG'
__LogRetain__ = '5'
__LogFileSize__ = '5000000'
