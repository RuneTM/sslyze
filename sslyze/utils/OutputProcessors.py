#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         sslyze.py
# Purpose:      Main module of SSLyze.
#
# Author:       aaron, alban, RuneTM
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

from xml.etree.ElementTree import Element, tostring
from xml.dom import minidom
import sys

try:
    from sslyze.utils.ServersConnectivityTester import ServersConnectivityTester
except ImportError:
    print '\nERROR: Could not import nassl Python module. Did you clone SSLyze\'s repo ? \n' +\
    'Please download the right pre-compiled package as described in the README.'
    sys.exit()

class XMLProcessor(object):
    """This processor generates output for a XML file"""

    def __init__(self):
        self.__tmp_results = []

    def _format_xml_target_result(self, target, result_list):
        (host, ip, port, sslVersion) = target
        target_xml = Element('target', host=host, ip=ip, port=str(port))
        result_list.sort(key=lambda result: result[0]) # Sort results

        for (command, plugin_result) in result_list:
            target_xml.append(plugin_result.get_xml_result())

        return target_xml

    def process(self, target, result_list):
        self.__tmp_results.append(self._format_xml_target_result(target, result_list))

    def output_results(self, shared_settings, exec_time, PROJECT_VERSION, PROJECT_URL, targets_ERR):
        result_xml_attr = {'httpsTunnel':str(shared_settings['https_tunnel_host']),
                           'totalScanTime' : str(exec_time),
                           'defaultTimeout' : str(shared_settings['timeout']),
                           'startTLS' : str(shared_settings['starttls'])}

        result_xml = Element('results', attrib = result_xml_attr)

        # Sort results in alphabetical order to make the XML files (somewhat) diff-able
        self.__tmp_results.sort(key=lambda xml_elem: xml_elem.attrib['host'])
        for xml_element in self.__tmp_results:
            result_xml.append(xml_element)

        xml_final_doc = Element('document', title = "SSLyze Scan Results",
                                SSLyzeVersion = PROJECT_VERSION,
                                SSLyzeWeb = PROJECT_URL)
        # Add the list of invalid targets
        xml_final_doc.append(ServersConnectivityTester.get_xml_result(targets_ERR))
        # Add the output of the plugins
        xml_final_doc.append(result_xml)

        # Hack: Prettify the XML file so it's (somewhat) diff-able
        xml_final_pretty = minidom.parseString(tostring(xml_final_doc, encoding='UTF-8'))
        with open(shared_settings['xml_file'],'w') as xml_file:
            xml_file.write(xml_final_pretty.toprettyxml(indent="  ", encoding="utf-8" ))
