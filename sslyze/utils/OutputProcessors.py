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
        results_dict = {
            'tag_name':'target',
            'attributes':{
                'host':host,
                'ip':ip,
                'port':str(port)
            },
            'sub':[]
        }
        result_list.sort(key=lambda result: result[0]) # Sort results

        for (command, plugin_result) in result_list:
            results_dict['sub'].append(plugin_result.get_result())
            #if plugin_result.get_result():
            #    with open('newtest.xml', 'w') as tmp_file:
            #        tmp_file.write(minidom.parseString(tostring(self.__generic_xml_outputter(plugin_result.get_result()), encoding='UTF-8')).toprettyxml(indent="  ", encoding="utf-8" ))

        return results_dict

    def process(self, target, result_list):
        self.__tmp_results.append(self._format_xml_target_result(target, result_list))

    def output_results(self, shared_settings, exec_time, PROJECT_VERSION, PROJECT_URL, targets_ERR):
        results_dict = {
            'tag_name':'results',
            'attributes':{
                'httpsTunnel':str(shared_settings['https_tunnel_host']),
                'totalScanTime':str(exec_time),
                'defaultTimeout':str(shared_settings['timeout']),
                'startTLS':str(shared_settings['starttls'])
            },
            'sub':[]
        }

        # Sort results in alphabetical order to make the XML files (somewhat) diff-able
        self.__tmp_results.sort(key=lambda xml_elem: xml_elem['attributes']['host'])
        for xml_element in self.__tmp_results:
            results_dict['sub'].append(xml_element)

        # Outermost level.
        document_dict = {
            'tag_name':'document',
            'attributes':{
                'title':'SSLyze Scan Results',
                'SSLyzeVersion':PROJECT_VERSION,
                'SSLyzeWeb':PROJECT_URL
            },
            'sub':[]
        }

        # Add the list of invalid targets
        document_dict['sub'].append(ServersConnectivityTester.get_result(targets_ERR))
        # Add the output of the plugins
        document_dict['sub'].append(results_dict)

        # Hack: Prettify the XML file so it's (somewhat) diff-able
        xml_final_pretty = minidom.parseString(tostring(self.__generic_xml_outputter(document_dict), encoding='UTF-8'))
        with open(shared_settings['xml_file'],'w') as xml_file:
            xml_file.write(xml_final_pretty.toprettyxml(indent="  ", encoding="utf-8" ))

    def __generic_xml_outputter(self, data_dict):
        """
        Recursive method that converts dict to xml.
        """
        outer_element = Element(
            data_dict['tag_name'],
            attrib=data_dict.get('attributes', {}))
        text = data_dict.get('text', None)
        if text:
            outer_element.text = text
        # Recurse through inner data
        for inner_element in data_dict.get('sub', []):
            outer_element.append(self.__generic_xml_outputter(inner_element))
        return outer_element
