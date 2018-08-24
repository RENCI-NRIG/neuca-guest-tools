#!/usr/bin/env python
#
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

import sys
import os

import time

from neuca_guest_tools import CONFIG, LOGGER
from neuca_guest_tools import __version__ as neuca_version
from neuca_guest_tools import _distro as neuca_distro
from neuca_guest_tools import _ConfDir as neuca_ConfDir
from neuca_guest_tools import _ConfFile as neuca_ConfFile
from neuca_guest_tools.customizer import get_customizer

import logging
import logging.handlers

from optparse import OptionParser
from daemon import runner
from lockfile import LockTimeout
""" This script performs distribution-specific customization at boot-time
based on EC2 user-data passed to the instance """


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
        self.pidfile_timeout = CONFIG.getint('runtime', 'pidfile-timeout')

        self.distro = neuca_distro
        self.log = logging.getLogger(LOGGER)
        self.customizer = None

        # Need to ensure that the state directory is created.
        if not os.path.exists(self.stateDir):
            os.makedirs(self.stateDir)

        # Ditto for PID directory.
        if not os.path.exists(self.pidDir):
            os.makedirs(self.pidDir)

    def run(self):
        self.log.info('distro: %s' % self.distro)
        self.customizer.buildIgnoredMacSet()

        while True:
            try:
                self.log.debug('Polling')
                self.customizer.updateInstanceData()
                self.customizer.updateHostname()
                self.customizer.updateNetworking()
                self.customizer.updateStorage()
                self.customizer.runNewScripts()
                self.customizer.firstRun = False
            except KeyboardInterrupt:
                self.log.error('Terminating on keyboard interrupt...')
                sys.exit(0)
            except Exception as e:
                self.log.exception(('Caught exception in daemon loop; ' +
                                    'backtrace follows.'))
                self.log.error('Exception was of type: %s' % (str(type(e))))
            time.sleep(10)


def check_daemon_liveness(daemonApp):
    running = False
    try:
        if os.path.exists(daemonApp.pidfile_path):
            lockfile = runner.make_pidlockfile(daemonApp.pidfile_path,
                                               daemonApp.pidfile_timeout)
            if not runner.is_pidfile_stale(lockfile):
                running = True
    except ValueError as ve:
        sys.stderr.write('Error in daemon PID lock file configuration.\n')
        sys.stderr.write('Error was: %s\n' % str(ve))
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(('Encountered an exception while checking if ' +
                          'PID file %s was stale.\n')
                         % daemonApp.pidfile_path)
        sys.stderr.write('Exception was of type: %s' % str(type(e)))
        sys.stderr.write('Exiting...')
        sys.exit(1)

    if running:
        sys.stderr.write(('Daemon is running, according to ' +
                          'PID lock file: %s\n' +
                          'Exiting...\n')
                         % daemonApp.pidfile_path)
        sys.exit(1)


def main():
    head, invokeName = os.path.split(sys.argv[0])

    if invokeName == 'neuca':
        print('Invoke as one of the following:')
        print('\tneuca-netconf - to configure host networking')
        print('\tneuca-user-script - ' +
              'to retrieve initial user-specified post-boot script')
        print('\tneuca-all-user-scripts - ' +
              'to retrieve all user-specified post-boot scripts')
        print('\tneuca-run-scripts - ' +
              'to execute any newly created user-specified post-boot scripts')
        print('\tneuca-user-data - to retrieve full user data')
        print('\tneuca-get - to retrieve specific items from user data')
        print('\tneuca-storage - ' +
              'to retrieve all storage devices configured')
        print('\tneuca-users - ' +
              'to retrieve all users configured')
        print('\tneuca-interfaces - ' +
              'to retrieve all network interfaces')
        print('\tneuca-routes - ' +
              'to show whether host has been specified ' +
              'as a router, and get all routes')
        print('\tneuca-get-public-ip - to show the public IP of the host')
        print('\tneuca-distro - to check distribution detection')
        print('\tneuca-version - to report the version of neuca in use')
        sys.exit(0)

    # Handle a couple of trivial invocation cases.
    if invokeName == 'neuca-distro':
        print neuca_distro
        sys.exit(0)

    if invokeName == 'neuca-version':
        print 'NEuca version ' + neuca_version
        sys.exit(0)

    # Not doing something trivial? Let's set things up.
    # First, determine the OS in use.
    customizer = get_customizer(neuca_distro)
    if customizer is None:
        sys.stderr.write('Distribution %s not supported.\n'
                         % neuca_distro)
        sys.exit(1)

    # Next, pull instance data.
    try:
        customizer.updateInstanceData()
    except:
        sys.stderr.write('Unable to perform initial ' +
                         'instance data retrieval.\n' +
                         'Attempting to proceed anyway...\n')

    # Now, attempt to read in the configuration file.
    config_file = neuca_ConfDir + '/' + neuca_ConfFile
    try:
        files_read = CONFIG.read(config_file)
        if len(files_read) == 0:
            sys.stderr.write(
                'Configuration file could not be read; ' +
                'proceeding with default settings.'
            )
    except Exception as e:
        sys.stderr.write('Unable to parse configuration file "%s": %s' %
                         (config_file, str(e)))
        sys.stderr.write('Exiting...')
        sys.exit(1)

    # Finally, create a daemon object instance;
    # we'll use it to check for daemon liveness, if nothing else.
    app = NEucad()
    app.customizer = customizer

    if invokeName == 'neuca-netconf':
        check_daemon_liveness(app)
        customizer.updateNetworking()

    if invokeName == 'neuca-run-scripts':
        check_daemon_liveness(app)
        customizer.runNewScripts()

    if invokeName == 'neuca-user-script':
        userScript = customizer.getBootScript()
        if userScript:
            print userScript
        else:
            print 'No user script found.'

    if invokeName == 'neuca-all-user-scripts':
        userScripts = customizer.getAllScripts()
        if userScripts is None:
            print "Not found"
        else :
            for script in userScripts:
                print script

    if invokeName == 'neuca-user-data':
        print customizer.getUserData()

    if invokeName == 'neuca-interfaces':
        interfaces = customizer.getAllInterfaces()
        if interfaces is None:
            print "Not found"
        else :
            print interfaces

    if invokeName == 'neuca-storage':
        storages = customizer.getAllStorage()
        if storages is None:
            print "Not found"
        else :
            print storages

    if invokeName == 'neuca-users':
        users = customizer.getAllUsers()
        if users is None:
            print "Not found"
        else :
            print users

    if invokeName == 'neuca-routes':
        print 'Router: ' + str(customizer.isRouter())
        routes = customizer.getAllRoutes()
        if routes is None:
            print "Not found"
        else :
            print routes

    if invokeName == 'neuca-get-public-ip':
        print customizer.getPublicIP()

    if invokeName == 'neuca-get':
        argv = sys.argv[1:]
        if len(argv) >= 2:
            section = argv[0]
            field = argv[1]
        elif (len(argv) == 1):
            section = 'global'
            field = argv[0]
        else:
            print 'usage: neuca-get [section] <field>'
            print 'section defaults to "global" if left unassigned'
            sys.exit(0)
        value = customizer.getUserDataField(section, field)
        if value is None:
            print "Not found"
        else:
            print value

    if invokeName == 'neucad':
        usagestr = 'Usage: %prog start|stop|restart [options]'
        parser = OptionParser(usage=usagestr)
        parser.add_option(
            '-f',
            '--foreground',
            dest='foreground',
            action='store_true',
            default=False,
            help='Run the service in foreground (useful for debugging).'
        )

        options, args = parser.parse_args()

        if len(args) != 1:
            parser.print_help()
            sys.exit(1)

        if args[0] == 'start':
            sys.argv = [sys.argv[0], 'start']
        elif args[0] == 'stop':
            sys.argv = [sys.argv[0], 'stop']
        elif args[0] == 'restart':
            sys.argv = [sys.argv[0], 'restart']
        else:
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
        log = logging.getLogger(LOGGER)
        log.setLevel(getattr(logging, CONFIG.get('logging', 'log-level')))

        # We must wait until here to create the DaemonRunner.
        # Otherwise, it overrides our help messages.
        daemon_runner = runner.DaemonRunner(app)

        if options.foreground:
            try:
                if runner.is_pidfile_stale(daemon_runner.pidfile):
                    daemon_runner.pidfile.break_lock()
                daemon_runner.pidfile.acquire()
            except LockTimeout:
                log.error(('PID file %s locked. ' +
                           'Exiting...')
                          % app.pidfile_path)
                sys.exit(1)
            except Exception as e:
                log.exception('PID file %s could not be acquired.'
                              % app.pidfile_path)
                log.error('Exception was of type: %s' % str(type(e)))
                log.error('Exiting...')
                sys.exit(1)

            try:
                log.info(
                    'Running service in foreground mode. ' +
                    'Press Control-c to stop.'
                )
                app.run()
            except KeyboardInterrupt:
                log.info(
                    'Stopping service at user request ' +
                    '(via keyboard interrupt). Exiting...'
                )
                sys.exit(0)
        else:
            log_dir = CONFIG.get('logging', 'log-directory')
            log_level = CONFIG.get('logging', 'log-level')

            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            handler = logging.handlers.RotatingFileHandler(
                log_dir + '/' + CONFIG.get('logging', 'log-file'),
                backupCount=CONFIG.getint('logging', 'log-retain'),
                maxBytes=CONFIG.getint('logging', 'log-file-size'))
            handler.setLevel(getattr(logging, log_level))
            formatter = logging.Formatter(log_format)
            handler.setFormatter(formatter)

            log.addHandler(handler)
            log.propagate = False
            log.info('Logging Started')

            daemon_runner.daemon_context.files_preserve = [
                handler.stream,
            ]
            try:
                log.info('Administrative operation: %s' % args[0])
                daemon_runner.do_action()
            except runner.DaemonRunnerStopFailureError as drsfe:
                log.propagate = True
                log.error(
                    'Unable to stop service; reason was: %s' % str(drsfe))
                log.error('Exiting...')
                sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
