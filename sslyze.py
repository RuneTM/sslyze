#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         sslyze.py
# Purpose:      Command line interface of SSLyze.
#
# Author:       aaron, alban
#
# Copyright:    2012 SSLyze developers
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

from time import time
from sslyze.utils.OutputClasses import RegularOutput, NoOutput
from sslyze.utils.OutputProcessors import XMLProcessor
from sslyze.sslyze_core import main, PROJECT_VERSION
from sys import exit as sys_exit

from sslyze.plugins import PluginsFinder

try:
    from sslyze.utils.CommandLineParser import CommandLineParser, CommandLineParsingError
    from sslyze.utils.ServersConnectivityTester import ServersConnectivityTester
except ImportError:
    print '\nERROR: Could not import nassl Python module. Did you clone SSLyze\'s repo ? \n' +\
    'Please download the right pre-compiled package as described in the README.'
    sys_exit()

def console_start():
    start_time = time()
    #--PLUGINS INITIALIZATION--
    sslyze_plugins = PluginsFinder()
    available_plugins = sslyze_plugins.get_plugins()
    available_commands = sslyze_plugins.get_commands()
    # Create the command line parser and the list of available options
    sslyze_parser = CommandLineParser(available_plugins, PROJECT_VERSION)
    try: # Parse the command line
        (command_list, target_list, shared_settings) = sslyze_parser.parse_command_line()
        output = NoOutput() if shared_settings['silence'] else RegularOutput()
        main(start_time, output, target_list, shared_settings, sslyze_plugins, available_plugins, available_commands)
    except CommandLineParsingError as e:
        print e.get_error_msg()
        return

if __name__ == "__main__":
    console_start()
