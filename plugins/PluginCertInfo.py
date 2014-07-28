#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCertInfo.py
# Purpose:      Verifies the target server's certificate validity against
#               Mozilla's trusted root store, and prints relevant fields of the
#               certificate.
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

from os.path import join, dirname
import imp

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl import X509_NAME_MISMATCH, X509_NAME_MATCHES_SAN, X509_NAME_MATCHES_CN
from nassl.SslClient import ClientCertificateRequested

TRUST_STORES_PATH = join(join(dirname(PluginBase.__file__), 'data'), 'trust_stores')

# We use the Mozilla store for additional things: OCSP and EV validation
MOZILLA_STORE_PATH = join(TRUST_STORES_PATH, 'mozilla.pem')

AVAILABLE_TRUST_STORES = \
    { MOZILLA_STORE_PATH :                       'Mozilla NSS - 01/2014',
      join(TRUST_STORES_PATH, 'microsoft.pem') : 'Microsoft - 04/2014',
      join(TRUST_STORES_PATH, 'apple.pem') :     'Apple - OS X 10.9.2',
      join(TRUST_STORES_PATH, 'java.pem') :      'Java 6 - Update 65'}

# Import Mozilla EV OIDs
MOZILLA_EV_OIDS = imp.load_source('mozilla_ev_oids',
                                  join(TRUST_STORES_PATH,  'mozilla_ev_oids.py')).MOZILLA_EV_OIDS

class PluginCertInfo(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCertInfo", description=(''))
    interface.add_command(
        command="certinfo",
        help= "Verifies the validity of the server(s) certificate(s) against "
            "various trust stores, checks for support for OCSP stapling, and "
            "prints relevant fields of "
            "the certificate. CERTINFO should be 'basic' or 'full'.",
        dest="certinfo")

    FIELD_FORMAT = '      {0:<35}{1}'.format
    TRUST_FORMAT = '\"{0}\" CA Store:'.format


    def process_task(self, target, command, arg):

        if arg == 'basic':
            textFunction  = self._get_basic_text
        elif arg == 'full':
            textFunction = self._get_full_text
        else:
            raise Exception("PluginCertInfo: Unknown command.")

        (host, _, _, _) = target
        threadPool = ThreadPool()

        for (storePath, _) in AVAILABLE_TRUST_STORES.iteritems():
            # Try to connect with each trust store
            threadPool.add_job((self._get_cert, (target, storePath)))

        # Start processing the jobs
        threadPool.start(len(AVAILABLE_TRUST_STORES))

        # Store the results as they come
        (verifyDict, verifyDictErr, x509Cert, ocspResp)  = ({}, {}, None, None)

        for (job, result) in threadPool.get_result():
            (_, (_, storePath)) = job
            (x509Cert, verifyStr, ocspResp) = result
            # Store the returned verify string for each trust store
            storeName = AVAILABLE_TRUST_STORES[storePath]
            verifyDict[storeName] = verifyStr

        if x509Cert is None:
            # This means none of the connections were successful. Get out
            for (job, exception) in threadPool.get_error():
                raise exception

        # Store thread pool errors
        for (job, exception) in threadPool.get_error():
            (_, (_, storePath)) = job
            errorMsg = '{} - {}'.format(exception.__class__.__name__, exception)

            storeName = AVAILABLE_TRUST_STORES[storePath]
            verifyDictErr[storeName] = errorMsg

        threadPool.join()

        # Results formatting
        # Primary results dict.
        results_dict = {
            'name':command,
            'attributes':{
                'argument':arg,
                'title':'Certificate Information'
            },
            'sub':[]
        }

        # Certificate information.
        cert_info_results = {
            'name':'certificate',
            'attributes':{
                'sha1Fingerprint':x509Cert.get_SHA1_fingerprint()
            },
            'sub':[]
        }

        if self._shared_settings['sni']:
            cert_info_results['attributes']['suppliedServerNameIndication'] = self._shared_settings['sni']

        # Add certificate in PEM format.
        cert_info_results['sub'].append({
            'name':'asPEM',
            'text':x509Cert.as_pem().strip()
        })

        # Certificate details.
        for (key, value) in x509Cert.as_dict().items():
            cert_info_results['sub'].append(self.__keyvalue_pair_to_dict(key, value))

        # Add results of certificate info to upper level dict.
        results_dict['sub'].append(cert_info_results)

        # Certificate validation results.
        cert_validation_results = {
            'name':'certificateValidation',
            'sub':[]
        }

        # Results of hostname validation.
        # TODO: Use SNI name for validation when --sni was used
        hostValDict = {
            X509_NAME_MATCHES_SAN : 'OK - Subject Alternative Name matches',
            X509_NAME_MATCHES_CN :  'OK - Common Name matches',
            X509_NAME_MISMATCH :    'FAILED - Certificate does NOT match ' + host
        }

        cert_validation_results['sub'].append({
            'name':'hostnameValidation',
            'attributes':{
                'serverHostname':host,
                'certificateMatchesServerHostname':str(x509Cert.matches_hostname(host) != X509_NAME_MISMATCH),
                'validationResult':hostValDict[x509Cert.matches_hostname(host)]
            }
        })

        # Results of path validation - OK.
        for (storeName, verifyStr) in verifyDict.iteritems():
            cert_store_results = {
                'name':'pathValidation',
                'attributes':{
                    'usingTrustStore':storeName,
                    'validationResult':verifyStr
                }
            }

            # EV certs - Only Mozilla supported for now
            if (verifyStr in 'ok') and ('Mozilla' in storeName):
                cert_store_results['attributes']['isExtendedValidationCertificate'] = str(self._is_ev_certificate(x509Cert))

            cert_validation_results['sub'].append(cert_store_results)

        # Results of path validation - errors.
        for (storeName, errorMsg) in verifyDictErr.iteritems():
            cert_validation_results['sub'].append({
                'name':'pathValidation',
                'attributes':{
                    'usingTrustStore':storeName,
                    'error':errorMsg
                }
            })

        # Add results of certificate validation to upper level dict.
        results_dict['sub'].append(cert_validation_results)

        # OCSP stapling.
        if ocspResp is None:
            ocsp_results = {
                'name':'ocspStapling',
                'attributes':{'error':'Server did not send back an OCSP response'}
            }
        else:
            ocsp_results = {
                'name':'ocspResponse',
                'attributes':{'isTrustedByMozillaCAStore':str(ocspResp.verify(MOZILLA_STORE_PATH))},
                'sub':[]
            }

            for (key, value) in ocspResp.as_dict().items():
                ocsp_results['sub'].append(self.__keyvalue_pair_to_dict(key, value))

        # Add results of OCSP stapling to upper level dict.
        results_dict['sub'].append(ocsp_results)

        return PluginBase.PluginResult(self.__cli_output(results_dict, textFunction(x509Cert)), results_dict)

    def __cli_output(self, results_dict, cert_txt):
        """
        Convert result dict into output for CLI.
        """        
        # Text output - certificate info
        outputTxt = [self.PLUGIN_TITLE_FORMAT('Certificate - Content')]
        outputTxt.extend(cert_txt)

        # Extract results from results_dict.
        certificate_results = results_dict['sub'][0]
        cert_validation_results = results_dict['sub'][1]
        ocsp_results = results_dict['sub'][2]
        # Child dicts from primary results.
        host_name_validation_results = cert_validation_results['sub'][0]

        # Text output - trust validation
        outputTxt.extend(['', self.PLUGIN_TITLE_FORMAT('Certificate - Trust')])

        # Hostname validation
        sni = certificate_results['attributes'].get('suppliedServerNameIndication', None)
        if sni:
            outputTxt.append(self.FIELD_FORMAT("SNI enabled with virtual domain:", sni))

        outputTxt.append(self.FIELD_FORMAT("Hostname Validation:",
                                            host_name_validation_results['attributes']['validationResult']))

        # Path validation results
        successful_results = []
        failed_results = []

        # Path validation is index 1 and up.
        for cert_store_result in cert_validation_results['sub'][1:]:
            # If succesful.
            storeName = validation_result = cert_store_result['attributes']['usingTrustStore']
            validation_result = cert_store_result['attributes'].get('validationResult', None)
            if validation_result:
                verifyTxt = 'OK - Certificate is trusted' if (validation_result in 'ok') \
                                                            else 'FAILED - Certificate is NOT Trusted: {}'.format(validation_result)
                # EV certs - Only Mozilla supported for now
                is_extended_validation_cert = cert_store_result['attributes'].get('isExtendedValidationCertificate', None)
                if is_extended_validation_cert and is_extended_validation_cert == 'True':
                    verifyTxt += ', Extended Validation'

                successful_results.append(self.FIELD_FORMAT(self.TRUST_FORMAT(storeName), verifyTxt))
            else:
                verifyTxt = 'ERROR: ' + cert_store_result['attributes']['error']
                failed_results.append(self.FIELD_FORMAT(self.TRUST_FORMAT(storeName), verifyTxt))

        # Add results to list.
        outputTxt.extend(successful_results)
        outputTxt.extend(failed_results)

        # Text output - OCSP stapling
        outputTxt.extend(['', self.PLUGIN_TITLE_FORMAT('Certificate - OCSP Stapling')])
        outputTxt.extend(self._get_ocsp_text(ocsp_results))
        return outputTxt

# FORMATTING FUNCTIONS

    def _get_ocsp_text(self, ocsp_results):

        if ocsp_results['attributes'].get('error', None):
            return [self.FIELD_FORMAT('Not supported: server did not send back an OCSP response.', '')]

        #ocspRespDict = ocspResp.as_dict()
        trusted_response = ocsp_results['attributes']['isTrustedByMozillaCAStore'] == 'True'
        ocspRespTrustTxt = 'Response is Trusted' if trusted_response else 'Response is NOT Trusted'

        # Convert OCSP data from ocsp_results to old style format.
        ocspRespDict = {}
        for result in ocsp_results['sub']:
            ocspRespDict[result['name']] = result['text'] if not result['text'] == u'' else result['sub']

        ocspRespTxt = [
            self.FIELD_FORMAT('OCSP Response Status:', ocspRespDict['responseStatus']),
            self.FIELD_FORMAT('Validation w/ Mozilla\'s CA Store:', ocspRespTrustTxt),
            self.FIELD_FORMAT('Responder Id:', ocspRespDict['responderID'])]

        if 'successful' not in ocspRespDict['responseStatus']:
            return ocspRespTxt

        # Convert OCSP data from ocsp_results to old style format.
        response_dict = {}
        for result in ocspRespDict['responses'][0]['sub']:
            # Special case, extract serial number.
            if result['name'] == 'certID':
                try:
                    response_dict[result['name']] = next(cert_id_info['text'] for cert_id_info in result['sub'] if cert_id_info['name'] == 'serialNumber')
                except StopIteration:
                    raise Exception('Something went wront during OCSP validation.')
            else:
                response_dict[result['name']] = result['text']

        ocspRespTxt.extend( [
            self.FIELD_FORMAT('Cert Status:', response_dict['certStatus']),
            self.FIELD_FORMAT('Cert Serial Number:', response_dict['certID']),
            self.FIELD_FORMAT('This Update:', response_dict['thisUpdate']),
            self.FIELD_FORMAT('Next Update:', response_dict['nextUpdate'])])

        return ocspRespTxt

    @staticmethod
    def _is_ev_certificate(cert):
        certDict = cert.as_dict()
        try:
            policy = certDict['extensions']['X509v3 Certificate Policies']['Policy']
            if policy[0] in MOZILLA_EV_OIDS:
                return True
        except:
            return False
        return False

    def _get_full_text(self, cert):
        return [cert.as_text()]

    def _get_basic_text(self, cert):
        certDict = cert.as_dict()

        try: # Extract the CN if there's one
            commonName = certDict['subject']['commonName']
        except KeyError:
            commonName = 'None'

        basicTxt = [
            self.FIELD_FORMAT("SHA1 Fingerprint:", cert.get_SHA1_fingerprint()),
            self.FIELD_FORMAT("Common Name:", commonName),
            self.FIELD_FORMAT("Issuer:", certDict['issuer']),
            self.FIELD_FORMAT("Serial Number:", certDict['serialNumber']),
            self.FIELD_FORMAT("Not Before:", certDict['validity']['notBefore']),
            self.FIELD_FORMAT("Not After:", certDict['validity']['notAfter']),
            self.FIELD_FORMAT("Signature Algorithm:", certDict['signatureAlgorithm']),
            self.FIELD_FORMAT("Key Size:", certDict['subjectPublicKeyInfo']['publicKeySize']),
            self.FIELD_FORMAT("Exponent:", "{0} (0x{0:x})".format(int(certDict['subjectPublicKeyInfo']['publicKey']['exponent'])))]

        try: # Print the SAN extension if there's one
            basicTxt.append(self.FIELD_FORMAT('X509v3 Subject Alternative Name:',
                                              certDict['extensions']['X509v3 Subject Alternative Name']))
        except KeyError:
            pass

        return basicTxt

    def _get_cert(self, target, storePath):
        """
        Connects to the target server and uses the supplied trust store to
        validate the server's certificate. Returns the server's certificate and
        OCSP response.
        """
        (_, _, _, sslVersion) = target
        sslConn = create_sslyze_connection(target, self._shared_settings,
                                           sslVersion,
                                           sslVerifyLocations=storePath)

        # Enable OCSP stapling
        sslConn.set_tlsext_status_ocsp()

        try: # Perform the SSL handshake
            sslConn.connect()

            ocspResp = sslConn.get_tlsext_status_ocsp_resp()
            x509Cert = sslConn.get_peer_certificate()
            (_, verifyStr) = sslConn.get_certificate_chain_verify_result()

        except ClientCertificateRequested: # The server asked for a client cert
            # We can get the server cert anyway
            ocspResp = sslConn.get_tlsext_status_ocsp_resp()
            x509Cert = sslConn.get_peer_certificate()
            (_, verifyStr) = sslConn.get_certificate_chain_verify_result()

        finally:
            sslConn.close()

        return (x509Cert, verifyStr, ocspResp)

    # Result generation.
    def __create_node(self, key, value=''):
        """
        Create a node for results dict.
        """
        key = key.replace(' ', '').strip() # Remove spaces
        key = key.replace('/', '').strip() # Remove slashes (S/MIME Capabilities)

        # Things that would generate invalid XML
        if key[0].isdigit(): # Tags cannot start with a digit
                key = 'oid-' + key

        node_results = {
            'name':key,
            'text':value.decode('utf-8').strip()
        }
        return node_results

    def __keyvalue_pair_to_dict(self, key, value=''):

        if type(value) is str: # value is a string
            key_results = self.__create_node(key, value)

        elif type(value) is int:
            key_results = self.__create_node(key, str(value))

        elif value is None: # no value
            key_results = self.__create_node(key)

        elif type(value) is list:
            key_results = self.__create_node(key)
            key_results['sub'] = []
            for val in value:
                key_results['sub'].append(self.__keyvalue_pair_to_dict('listEntry', val))

        elif type(value) is dict: # value is a list of subnodes
            key_results = self.__create_node(key)
            key_results['sub'] = []
            for subkey, subvalue in value.items():
                key_results['sub'].append(self.__keyvalue_pair_to_dict(subkey, subvalue))
        else:
            raise Exception()

        return key_results
