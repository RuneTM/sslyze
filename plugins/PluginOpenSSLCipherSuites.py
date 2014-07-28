#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginOpenSSLCipherSuites.py
# Purpose:      Scans the target server for supported OpenSSL cipher suites.
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

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.SSLyzeSSLConnection import create_sslyze_connection, SSLHandshakeRejected
from nassl import SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2
from nassl.SslClient import SslClient


class PluginOpenSSLCipherSuites(PluginBase.PluginBase):


    interface = PluginBase.PluginInterface(
        "PluginOpenSSLCipherSuites",
        "Scans the server(s) for supported OpenSSL cipher suites.")
    interface.add_command(
        command="sslv2",
        help="Lists the SSL 2.0 OpenSSL cipher suites supported by the server(s).",
        aggressive=False)
    interface.add_command(
        command="sslv3",
        help="Lists the SSL 3.0 OpenSSL cipher suites supported by the server(s).",
        aggressive=True)
    interface.add_command(
        command="tlsv1",
        help="Lists the TLS 1.0 OpenSSL cipher suites supported by the server(s).",
        aggressive=True)
    interface.add_command(
        command="tlsv1_1",
        help="Lists the TLS 1.1 OpenSSL cipher suites supported by the server(s).",
        aggressive=True)
    interface.add_command(
        command="tlsv1_2",
        help="Lists the TLS 1.2 OpenSSL cipher suites supported by the server(s).",
        aggressive=True)
    interface.add_option(
        option='http_get',
        help="Option - For each cipher suite, sends an HTTP GET request after "
        "completing the SSL handshake and returns the HTTP status code.")
    interface.add_option(
        option='hide_rejected_ciphers',
        help="Option - Hides the (usually long) list of cipher suites that were"
        " rejected by the server(s).")


    def process_task(self, target, command, args):

        MAX_THREADS = 15
        sslVersionDict = {'sslv2': SSLV2,
                       'sslv3': SSLV3,
                       'tlsv1': TLSV1,
                       'tlsv1_1': TLSV1_1,
                       'tlsv1_2': TLSV1_2}
        try:
            sslVersion = sslVersionDict[command]
        except KeyError:
            raise Exception("PluginOpenSSLCipherSuites: Unknown command.")

        # Get the list of available cipher suites for the given ssl version
        sslClient = SslClient(sslVersion=sslVersion)
        sslClient.set_cipher_list('ALL:COMPLEMENTOFALL')
        cipher_list = sslClient.get_cipher_list()

        # Create a thread pool
        NB_THREADS = min(len(cipher_list), MAX_THREADS) # One thread per cipher
        thread_pool = ThreadPool()

        # Scan for every available cipher suite
        for cipher in cipher_list:
            thread_pool.add_job((self._test_ciphersuite,
                                 (target, sslVersion, cipher)))

        # Scan for the preferred cipher suite
        thread_pool.add_job((self._pref_ciphersuite,
                             (target, sslVersion)))

        # Start processing the jobs
        thread_pool.start(NB_THREADS)

        cipher_result_dicts = {
            'preferredCipherSuite':[],
            'acceptedCipherSuites':[],
            'errors':[],
            'rejectedCipherSuites':[]
        }

        # Store the results as they come
        for completed_job in thread_pool.get_result():
            (job, result) = completed_job
            if result is not None:
                (result_type, ssl_cipher, keysize, msg) = result
                cipher_result_dicts[result_type].append(self.__process_cipher_data(ssl_cipher, msg, keysize))

        # Store thread pool errors
        for failed_job in thread_pool.get_error():
            (job, exception) = failed_job
            ssl_cipher = str(job[1][2])
            error_msg = '{} - {}'.format(exception.__class__.__name__, exception)
            cipher_result_dicts['errors'].append(self.__process_cipher_data(ssl_cipher, error_msg, None))

        thread_pool.join()

        # Results.
        results_dict = {
                'name':command,
                'attributes':{'title':'{} Cipher Suites'.format(command.upper())},
                'sub':[]
            }

        # Sort cipher results and append to results dict.
        for result_type, cipher_result in cipher_result_dicts.items():
            results_dict['sub'].append({
                'name':result_type,
                'sub':sorted(cipher_result, key=lambda cipher: cipher['attributes']['name'])
            })
            
        return PluginBase.PluginResult(self._generate_text_output(results_dict), results_dict)

    def __process_cipher_data(self, cipher_name, msg, keysize):
        """
        Prepare data for cipher result dict.
        """
        tmp_cipher_result = {
            'name':'cipherSuite',
            'attributes':{
                'name':cipher_name,
                'connectionStatus':msg,
                'anonymous':str(True) if 'ADH' in cipher_name or 'AECDH' in cipher_name else str(False)
            }
        }
        if keysize:
            tmp_cipher_result['attributes']['keySize'] = str(keysize)
        return tmp_cipher_result

# FORMATTING FUNCTIONS
    def _generate_text_output(self, results_dict):

        cipherFormat = '                 {0:<32}{1:<35}'.format
        titleFormat =  '      {0:<32} '.format
        keysizeFormat = '{0:<30}{1:<14}'.format

        txtTitle = self.PLUGIN_TITLE_FORMAT(results_dict['attributes']['title'])
        txtOutput = []

        translate_dict = {
            'preferredCipherSuite':'Preferred:',
            'acceptedCipherSuites':'Accepted:',
            'errors':'Undefined - An unexpected error happened:',
            'rejectedCipherSuites':'Rejected:'
        }

        # Iterate over each type of cipher result.
        for result_type_list in results_dict['sub']:
            if self._shared_settings['hide_rejected_ciphers'] and result_type_list['name'] == 'rejectedCipherSuites':
                continue
            # Only care about lists with ciphers.
            if len(result_type_list['sub']) > 0:
                # Title.
                txtOutput.append(titleFormat(translate_dict[result_type_list['name']]))
                # One line per cipher
                for cipher_result in result_type_list['sub']:
                    cipher_txt = cipher_result['attributes']['name']
                    if cipher_result['attributes'].get('keySize', None):
                        if cipher_result['attributes']['anonymous'] == 'True':
                            keysize = 'ANON'
                        else:
                            keysize = '{} bits'.format(cipher_result['attributes']['keySize'])
                        cipher_txt = keysizeFormat(cipher_txt, keysize)
                    txtOutput.append(cipherFormat(cipher_txt, cipher_result['attributes']['connectionStatus']))
        if txtOutput == []:
            # Server rejected all cipher suites
            txtOutput = [txtTitle, '      Server rejected all cipher suites.']
        else:
            txtOutput = [txtTitle] + txtOutput

        return txtOutput

# SSL FUNCTIONS
    def _test_ciphersuite(self, target, ssl_version, ssl_cipher):
        """
        Initiates a SSL handshake with the server, using the SSL version and
        cipher suite specified.
        """
        sslConn = create_sslyze_connection(target, self._shared_settings, ssl_version)
        sslConn.set_cipher_list(ssl_cipher)

        try: # Perform the SSL handshake
            sslConn.connect()

        except SSLHandshakeRejected as e:
            return 'rejectedCipherSuites', ssl_cipher, None, str(e)

        except:
            raise

        else:
            ssl_cipher = sslConn.get_current_cipher_name()
            keysize = sslConn.get_current_cipher_bits()
            status_msg = sslConn.post_handshake_check()
            return 'acceptedCipherSuites', ssl_cipher, keysize, status_msg

        finally:
            sslConn.close()


    def _pref_ciphersuite(self, target, ssl_version):
        """
        Initiates a SSL handshake with the server, using the SSL version and cipher
        suite specified.
        """
        sslConn = create_sslyze_connection(target, self._shared_settings, ssl_version)

        try: # Perform the SSL handshake
            sslConn.connect()
            ssl_cipher = sslConn.get_current_cipher_name()
            keysize = sslConn.get_current_cipher_bits()
            status_msg = sslConn.post_handshake_check()
            return 'preferredCipherSuite', ssl_cipher, keysize, status_msg

        except:
            return None

        finally:
            sslConn.close()
