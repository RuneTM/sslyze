#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginSessionRenegotiation.py
# Purpose:      Tests the target server for insecure renegotiation.
#
# Author:       alban
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

import socket
from xml.etree.ElementTree import Element

from sslyze.plugins import PluginBase
from sslyze.utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl._nassl import OpenSSLError


class PluginSessionRenegotiation(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginSessionRenegotiation",  "")
    interface.add_command(
        command="reneg",
        help=(
            "Tests the server(s) for client-initiated "
            'renegotiation and secure renegotiation support.'))


    def process_task(self, target, command, args):
        (clientReneg, secureReneg) = self._test_renegotiation(target)
        
        # Results.
        results_dict = {
            'tag_name':command,
            'attributes':{'title':'Session Renegotiation'},
            'sub':[{
                'tag_name':'sessionRenegotiation',
                'attributes':{
                    'canBeClientInitiated' : str(clientReneg),
                    'isSecure' : str(secureReneg)
                    }
            }]
        }

        return PluginBase.PluginResult(self.__cli_output(results_dict), self.__xml_output(results_dict), results_dict)

    def __cli_output(self, results_dict):
        """
        Convert result dict into output for CLI.
        """
        clientTxt = 'Honored' if results_dict['sub'][0]['attributes']['canBeClientInitiated'] == 'True' else 'Rejected'
        secureTxt = 'Supported' if results_dict['sub'][0]['attributes']['isSecure'] == 'True' else 'Not supported'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(results_dict['attributes']['title'])]

        outFormat = '      {0:<35}{1}'.format
        txtOutput.append(outFormat('Client-initiated Renegotiations:', clientTxt))
        txtOutput.append(outFormat('Secure Renegotiation:', secureTxt))
        return txtOutput

    def __xml_output(self, results_dict):
        """
        Old code to generate XML from results_dict.
        """
        xmlReneg = Element('sessionRenegotiation',
                           attrib = {'canBeClientInitiated' : results_dict['sub'][0]['attributes']['canBeClientInitiated'],
                                     'isSecure' : results_dict['sub'][0]['attributes']['isSecure']})

        xmlOutput = Element(results_dict['tag_name'], title=results_dict['attributes']['title'])
        xmlOutput.append(xmlReneg)
        return xmlOutput

    def _test_renegotiation(self, target):
        """
        Checks whether the server honors session renegotiation requests and
        whether it supports secure renegotiation.
        """
        sslConn = create_sslyze_connection(target, self._shared_settings)

        try: # Perform the SSL handshake
            sslConn.connect()
            secureReneg = sslConn.get_secure_renegotiation_support()

            try: # Let's try to renegotiate
                sslConn.do_renegotiate()
                clientReneg = True

            # Errors caused by a server rejecting the renegotiation
            except socket.error as e:
                if 'connection was forcibly closed' in str(e.args):
                    clientReneg = False
                elif 'reset by peer' in str(e.args):
                    clientReneg = False
                else:
                    raise
            #except socket.timeout as e:
            #    result_reneg = 'Rejected (timeout)'
            except OpenSSLError as e:
                if 'handshake failure' in str(e.args):
                    clientReneg = False
                elif 'no renegotiation' in str(e.args):
                    clientReneg = False
                else:
                    raise

            # Should be last as socket errors are also IOError
            except IOError as e:
                if 'Nassl SSL handshake failed' in str(e.args):
                    clientReneg = False
                else:
                    raise

        finally:
            sslConn.close()

        return (clientReneg, secureReneg)
