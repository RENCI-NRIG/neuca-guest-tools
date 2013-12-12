import platform

__version__ = '1.4'
__distro__ = platform.dist()[0]
__logdir__ = '/var/log/neuca'
__logfile__ = 'neuca-agent.log'
__rundir__ = '/var/run/neuca'
__pidfile__ = 'neucad.pid'
