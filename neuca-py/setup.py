#!/usr/bin/env python

from distutils.core import setup
from neuca_guest_tools import __version__

setup(name = 'neuca_guest_tools',
      version = __version__,
      packages = ['neuca_guest_tools'],
      scripts = ['neuca'],
)
