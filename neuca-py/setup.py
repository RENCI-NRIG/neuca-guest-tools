#!/usr/bin/env python

import os
import distutils.log

from distutils.core import setup
from distutils.command.install import install
from errno import EEXIST
from neuca_guest_tools import __version__

wrapper_script = 'neuca'
wrapper_aliases = ['neuca-netconf', 'neuca-user-script', 'neuca-all-user-scripts',
                   'neuca-run-scripts', 'neuca-user-data', 'neuca-get', 'neuca-routes',
                   'neuca-get-public-ip', 'neuca-distro', 'neuca-version', 'neucad']

class neuca_install(install):
    def run(self):
        # Run the default setup tasks
        install.run(self)
        # Now, on POSIX platforms, create the symlinks to the wrapper script
        if os.name == 'posix':
            curr_dir = os.getcwd()
            distutils.log.info('performing post-install operations...')
            os.chdir(self.install_scripts)
            distutils.log.info('creating required symlinks in %s', self.install_scripts)
            for alias in wrapper_aliases:
                distutils.log.info('symlinking %s -> %s', wrapper_script, alias)
                try:
                    os.symlink(wrapper_script, alias)
                except OSError, e:
                    if e.errno != EEXIST:
                        raise
            os.chdir(curr_dir)
            distutils.log.info('post-install operations completed')


setup(name = 'neuca_guest_tools',
      version = __version__,
      packages = ['neuca_guest_tools'],
      scripts = [wrapper_script],
      cmdclass = {"install": neuca_install},
)
