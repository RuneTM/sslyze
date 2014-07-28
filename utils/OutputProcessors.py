#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         OutPutProcessors.py
# Purpose:      Convert results into xml and/or json files.
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

from xml.etree.ElementTree import Element, tostring
from xml.dom import minidom
from json import dumps

def output_xml(document_dict, shared_settings):
    """Output results dict to a XML file."""
    # Hack: Prettify the XML file so it's (somewhat) diff-able
    xml_final = minidom.parseString(tostring(__generic_xml_outputter(document_dict), encoding='UTF-8'))
    with open(shared_settings['xml_file'],'w') as xml_file:
        xml_file.write(xml_final.toprettyxml(indent="  ", encoding="utf-8" ))

def __generic_xml_outputter(data_dict):
    """
    Recursive method that converts dict to xml.
    """
    outer_element = Element(
        data_dict['name'],
        attrib=data_dict.get('attributes', {}))
    text = data_dict.get('text', None)
    if text:
        outer_element.text = text
    # Recurse through inner data
    for inner_element in data_dict.get('sub', []):
        outer_element.append(__generic_xml_outputter(inner_element))
    return outer_element

def output_json(document_dict, shared_settings):
    """Output results dict to a file formatted as JSON."""
    with open(shared_settings['json_file'],'w') as json_file:
        json_file.write(dumps(document_dict))
