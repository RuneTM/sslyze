#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginHSTS.py
# Purpose:      Checks if the server supports RFC 6797 HTTP Strict Transport
#               Security by checking if the server responds with the
#               Strict-Transport-Security field in the header.
#
#               Note: There is currently no support for hsts pinning.
#
#               This plugin is based on the plugin written by Tom Samstag
#               (tecknicaltom) and reworked, integrated and adapted to the
#               new sslyze plugin API by Joachim Strömbergson.
#
# Author:       tecknicaltom, joachims, alban
#
# Copyright:    2013 SSLyze developers
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

from xml.etree.ElementTree import Element
from sslyze.utils.HTTPResponseParser import parse_http_response
from sslyze.utils.SSLyzeSSLConnection import create_sslyze_connection
from sslyze.plugins import PluginBase
from urlparse import urlparse
import Cookie


class PluginHSTS(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHSTS", description=(''))
    interface.add_command(
        command="hsts",
        help="Checks support for HTTP Strict Transport Security "
             "(HSTS) by collecting any Strict-Transport-Security field present in "
             "the HTTP response sent back by the server(s).",
        dest=None)


    def process_task(self, target, command, args):
        if self._shared_settings['starttls']:
            raise Exception('Cannot use --hsts with --starttls.')

        hsts_header = self._get_hsts_header(target)
        hsts_supported = True if hsts_header else None

        # Results.
        results_dict = {
            'tag_name':'hsts',
            'attributes':{'title':'HTTP Strict Transport Security'},
            'sub':[{
                'tag_name':'hsts',
                'attributes':{'sentHstsHeader':str(hsts_supported)}
            }]
        }

        if hsts_supported:
            results_dict['sub'][0]['attributes']['hstsHeaderValue'] = hsts_header

        return PluginBase.PluginResult(self.__cli_output(results_dict), self.__xml_output(results_dict), results_dict)

    def __cli_output(self, results_dict):
        """
        Convert result dict into output for CLI.
        """
        FIELD_FORMAT = '      {0:<35}{1}'.format
        txt_result = [self.PLUGIN_TITLE_FORMAT(results_dict['attributes']['title'])]
        hsts_header = results_dict['sub'][0]['attributes'].get('hstsHeaderValue', None)
        if hsts_header:
            txt_result.append(FIELD_FORMAT("Supported:", hsts_header))
        else:
            txt_result.append(FIELD_FORMAT("Not supported: server did not send an HSTS header.", ""))
        return txt_result

    def __xml_output(self, results_dict):
        """
        Old code to generate XML from results_dict.
        """
        xml_result = Element('hsts', title=results_dict['attributes']['title'])
        xml_hsts_attr = {'sentHstsHeader': results_dict['sub'][0]['attributes']['sentHstsHeader']}
        hsts_header = results_dict['sub'][0]['attributes'].get('hstsHeaderValue', None)
        if hsts_header:
            xml_hsts_attr['hstsHeaderValue'] = hsts_header
        xml_hsts = Element('hsts', attrib=xml_hsts_attr)
        xml_result.append(xml_hsts)
        return xml_result

    def _get_hsts_header(self, target):

        hstsHeader = None
        MAX_REDIRECT = 5
        nb_redirect = 0
        httpGetFormat = 'GET {0} HTTP/1.0\r\nHost: {1}\r\n{2}Connection: close\r\n\r\n'.format
        httpPath = '/'
        httpAppend = ''    
        
        while nb_redirect < MAX_REDIRECT:
            sslConn = create_sslyze_connection(target, self._shared_settings)
            
            # Perform the SSL handshake
            sslConn.connect()
            
            sslConn.write(httpGetFormat(httpPath, target[0], httpAppend))
            httpResp = parse_http_response(sslConn.read(2048))
            sslConn.close()
            
            if httpResp.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                raise Exception('Server did not return an HTTP response')
            elif 300 <= httpResp.status < 400:
                redirectHeader = httpResp.getheader('Location', None)
                cookieHeader = httpResp.getheader('Set-Cookie', None)
                
                if redirectHeader is None:
                    break
                
                o = urlparse(redirectHeader)
                httpPath = o.path
                
                # Handle absolute redirection URL
                if o.hostname:
                    if o.port:
                        port = o.port
                    else:
                        if o.scheme == 'https':
                            port = 443
                        elif o.scheme == 'http':
                            # We would have to use urllib for http: URLs
                            raise Exception("Error: server sent a redirection to HTTP.")
                        else:
                            port = target[2]
                        
                    target = (o.hostname, o.hostname, port, target[3])
                
                # Handle cookies
                if cookieHeader:
                    cookie = Cookie.SimpleCookie(cookieHeader)
                    
                    if cookie:
                        httpAppend = 'Cookie:' + cookie.output(attrs=[], header='', sep=';') + '\r\n'
                
                nb_redirect+=1
            else:
                hstsHeader = httpResp.getheader('strict-transport-security', None)
                break
        
        return hstsHeader


