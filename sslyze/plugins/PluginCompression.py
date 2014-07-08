#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCompression.py
# Purpose:      Tests the server for Zlib compression support.
#
# Author:       tritter, alban
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

from xml.etree.ElementTree import Element

from sslyze.plugins import PluginBase
from sslyze.utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl.SslClient import ClientCertificateRequested


class PluginCompression(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCompression", description="")
    interface.add_command(
        command="compression",
        help="Tests the server(s) for Zlib compression support.")


    def process_task(self, target, command, args):
        sslConn = create_sslyze_connection(target, self._shared_settings)
        # Make sure OpenSSL was built with support for compression to avoid false negatives
        if 'zlib compression' not in sslConn.get_available_compression_methods():
            raise RuntimeError('OpenSSL was not built with support for zlib / compression. Did you build nassl yourself ?')

        try: # Perform the SSL handshake
            sslConn.connect()
            compName = sslConn.get_current_compression_method()
        except ClientCertificateRequested: # The server asked for a client cert
            compName = sslConn.get_current_compression_method()
        finally:
            sslConn.close()

        # Results.
        results_dict = {
            'tag_name':command,
            'attributes':{'title':'Compression'},
        }

        if compName:
            results_dict['sub'] = [{
                'tag_name':'compressionMethod',
                'attributes':{'type':'DEFLATE'}
            }]
        return PluginBase.PluginResult(self.__cli_output(results_dict), self.__xml_output(results_dict), results_dict)

    def __cli_output(self, results_dict):
        """
        Convert result dict into output for CLI.
        """
        OUT_FORMAT = '      {0:<35}{1}'.format
        if results_dict.get('sub', None):
            compTxt = 'Supported'
        else:
            compTxt = 'Disabled'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(results_dict['attributes']['title'])]
        txtOutput.append(OUT_FORMAT("DEFLATE Compression:", compTxt))
        #print txtOutput
        return txtOutput

    def __xml_output(self, results_dict):
        """
        Old code to generate XML from results_dict.
        """
        # XML output
        xmlOutput = Element(results_dict['tag_name'], title=results_dict['attributes']['title'])
        if results_dict.get('sub', None):
            xmlNode = Element('compressionMethod', type="DEFLATE")
            xmlOutput.append(xmlNode)
        return xmlOutput
