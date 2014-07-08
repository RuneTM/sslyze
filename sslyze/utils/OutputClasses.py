#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         OutputClasses.py
# Purpose:      Controls what output is printed.
#
# Author:       aaron, alban
#
# Copyright:    2014 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------
import sys

try:
    from sslyze.utils.ServersConnectivityTester import ServersConnectivityTester
except ImportError:
    print '\nERROR: Could not import nassl Python module. Did you clone SSLyze\'s repo ? \n' +\
    'Please download the right pre-compiled package as described in the README.'
    sys.exit()

SCAN_FORMAT = 'Scan Results For {0}:{1} - {2}:{1}'

def _format_title(title):
    return ' {}\n {}'.format(title.upper(), '-' * len(title))

def _format_txt_target_result(target, result_list):
    (host, ip, port, sslVersion) = target
    target_result_str = ''

    for (command, plugin_result) in result_list:
        # Print the result of each separate command
        target_result_str = '{}\n'.format(target_result_str)
        for line in plugin_result.get_txt_result():
            target_result_str = '{}{}\n'.format(target_result_str, line)

    scan_txt = SCAN_FORMAT.format(host, port, ip)
    return '{}\n{}\n\n'.format(_format_title(scan_txt), target_result_str)

class RegularOutput(object):
    """This output class prints output to console."""

    def available_plugins(self):
        print '\n\n\n{}\n'.format(_format_title('Registering available plugins'))

    def plugin_name(self, name):
        print '  {}'.format(name)

    def host_availability(self):
        print '\n\n\n{}'.format(_format_title('Checking host(s) availability'))

    def server_connectivity_test(self, targets_OK, targets_ERR):
        print '{}\n\n\n'.format(ServersConnectivityTester.get_printable_result(targets_OK, targets_ERR))

    def results(self, target, result):
        print _format_txt_target_result(target, result)

    def scan_complete(self, exec_time):
        print _format_title('Scan Completed in {0:.2f} s'.format(exec_time))

class NoOutput(object):
    """This output class does not print anything"""

    def available_plugins(self):
        pass

    def plugin_name(self, name):
        pass

    def host_availability(self):
        pass

    def server_connectivity_test(self, targets_OK, targets_ERR):
        pass

    def results(self, target, result_dict):
        pass

    def scan_complete(self, exec_time):
        pass


class ScanProblem(Exception):
    """Raised when it is not possible to continue scanning"""
    pass
