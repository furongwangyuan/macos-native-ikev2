#!/usr/bin/env python3
"""Run isolated source tests. OS mutations, sockets and subprocesses are denied."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / 'server/runtime'))


def forbidden(*args, **kwargs):
    raise AssertionError('A real OS/network effect escaped the offline fixture')


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Run these tests as an ordinary user.')
    with patch.object(subprocess, 'Popen', side_effect=forbidden), \
         patch.object(socket, 'socket', side_effect=forbidden), \
         patch.object(os, 'system', side_effect=forbidden):
        suite = unittest.defaultTestLoader.discover(str(HERE), pattern='test_*.py')
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
