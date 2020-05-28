"""
#for any help related with this script execute help('Setup') on python console.

SYNOPSIS:
This is a setup script for generating key file (aesKey.yaml), configuration file(credentials.yaml) and initialization file(init.yaml)
Original creation date: March 2020
Version:1.0
Team:DTC_pDXCsquad1
DL:DTC_BLR_pDXCSquad@dxc.com

DESCRIPTION:
This script will create the initialization parameters and store in init.yaml.
Also store the Dell OME user access password and API user access password in an
encrypted format for the Invoke script to use when sending event information from the
DellOME monitoring tool to the PDXC API gateway.

user input Parameter:
DElLOME_ip_address
DEllOME_username
DellOME_password
DellOME_severities name: [1=Unknown,2=Info,4=Normal,8=Warning,16=Critical]
status_type name: [1000-Acknowledged ,2000-Not-Acknowledged]
Time_frequnecy: [accept time in minutes] ex:20
pdxc_url
pdxc_username
pdxc_password

EXAMPLE:
py setup.py

OUTPUT:
Creates a key file used for encryption and decryption - aesKey.yaml
Creates a configuration file used to store encrypted passwords - credentials.yaml
Creates a initialization file used to store initialization parameters - init.yaml
Creates a log file - Setup.log

"""
import json
import requests
import getpass
import base64
import urllib3
import yaml
import os
import ssl
import re
import logging
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')
file_handler = logging.FileHandler('Setup.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

encrypted_data = {}
configuration_file = {}
key_data={}
suffix_get = "/dxc/events/R1/"
suffix_create = "create"
key = get_random_bytes(16)

try:
    def encrypt_credentials(cred):
        """
                This function encrypts credentials passed by user as inputs
                :param cred:
                :return: base64_message:
         """
        message = cred
        message_bytes = message.encode('ascii')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        encrypted_bytes = iv + cipher.encrypt(message_bytes)
        base64_encrypted_bytes = base64.b64encode(encrypted_bytes)
        base64_encrypted_message = base64_encrypted_bytes.decode('ascii')
        return base64_encrypted_message

    def DellOMEIpCheck(DellOME_ip_address):
        """
        This function validates the format of IP Address passed by user
        :param DellOME_ip_address:
        :return: 1 if IP Address is valid:
        :return: 0 if IP Address is not valid:
        """
        regex = '''^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$'''
        if (re.search(regex, DellOME_ip_address)):
            return 1
        else:
            return 0

    def DellOMEApiCall(DellOME_ip_address, DellOME_username, DellOME_password):
        """
        This function fetches session_id to validate DellOME API call
        :param DellOME_ip_address:
        :param DellOME_username:
        :param DellOME_password:
        :return: sessid:
        """
        logger.debug("---Inside get sessionId of DellOME---")
        sessid = ""
        try:
            base_url = 'https://%s' % DellOME_ip_address
            session_url = base_url + "/api/SessionService/Sessions"

            headers1 = {"Content-Type": "application/json"}
            user_details = {'UserName': DellOME_username,
                            'Password': DellOME_password,
                            'SessionType': 'API'}

            session_info = requests.post(session_url, verify=False,
                                         data=json.dumps(user_details),
                                         headers=headers1)
            if session_info.status_code == 201:

                output = session_info.json()
                j1 = json.dumps(output)
                dict = json.loads(j1)
                sessid = (dict['Id'])
            else:
                logger.error("getting error response from Dell Ome with status code:{}".format(session_info.status_code))

        except requests.exceptions.URLRequired as e:
            logger.error("valid url is required", exc_info=True)
        except requests.exceptions.HTTPError as e:
            logger.error("HTTP error as occured",exc_info=True)
        except requests.exceptions.ConnectionError as e:
            logger.error("connection error occured",exc_info=True)
        except requests.exceptions.TooManyRedirects as e:
            logger.error("Too many redirects",exc_info=True)
        except requests.exceptions.RequestException as e:
            logger.error("There was an ambiguous exception that occurred while handling your request.",exc_info=True)
        except Exception as e:
            logger.error("Invalid DellOME credentials or DellOME IP address",exc_info=True)
        return sessid

    def severities(DellOME_severity):
        """
        This function validates severities passed by user
        :param DellOME_severities:
        :return: None if severity provided not in valid_severities set:
        :return: checked_severities if severities provided is in valid_severities set:
        """
        logger.debug("---Inside checking valid severities---")
        DellOME_severity = DellOME_severity.lower()
        DellOME_severity = DellOME_severity.split(",")
        valid_severities = ['info', 'unknown' , 'critical' , 'warning' , 'normal']
        checked_severities = []
        for severity in DellOME_severity:
            if severity not in valid_severities:
                return
            else:
                checked_severities.append(severity)
        return (",".join(checked_severities))

    def statusType(DellOME_statusType):
        logger.debug("---Inside checking valid status name---")
        DellOME_statusType = DellOME_statusType.lower()
        DellOME_statusType = DellOME_statusType.split(",")
        valid_statusType = ['acknowledged','not acknowledged']
        checked_statusType = []
        for status in DellOME_statusType:
            if status not in valid_statusType:
                return
            else:
                checked_statusType.append(status)
        return (",".join(checked_statusType))

    def get_util_api(pdxc_environment):
        """
        This function fetches the the url keys for the API based on the desired environment
        :param pdxc_environment:
        :return: url:
        """
        logger.debug("---Inside create api url based on desired environment---")
        url = ""
        if pdxc_environment == 'dev':
            url = "https://api.platformdxc-d0.com/int3-dev/"
        elif pdxc_environment == 'sandbox2':
            url = "https://api.platformdxc-sb2.com/int3-dev/"
        elif pdxc_environment == 'dev2':
            url = "https://api.platformdxc-d2.com/int3-api/"
        elif pdxc_environment == 'devqa':
            url = "https://api.platformdxc-qa.com/int3-api/"
        elif pdxc_environment == 'globalpreprod':
            url = "https://api.ie00-platformdxc-st.com/int3-api/"
        elif pdxc_environment == 'test':
            url = "https://api.platformdxc-t0.com/int3-api/"
        elif pdxc_environment == 'globalprod':
            url = "https://api.ie00-platformdxc.com/int3-api/"
        elif pdxc_environment == 'uspreprod':
            url = "https://api.ie00-platformdxc-st.com/int3-api/"
        elif pdxc_environment == 'usprod':
            url = "https://api.ie00-platformdxc-st.com/int3-api/"
        else:
            logger.error("The Environment provided {} is not a valid option".format(pdxc_environment))
        return url

    def constructApiurl(url):
        """
        This function constructs the API URL based on the desired environment
        :param url:
        :return: pdxc_api_url:
        """
        logger.debug("---Inside construct api url ---")
        data = url + "/dxc/integration/R1/api-gateway/apis?restApiName=Events"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        response = requests.get(data, headers=headers, verify=False)
        response_json = response.json()
        base_url = response_json['Url']
        pdxc_api_url = base_url + suffix_get
        return pdxc_api_url

    def pdxcApiCall(pdxc_api_url, pdxc_api_username, pdxc_api_password):
        """
        This function validates the PDXC API call with credentials passed by user to a PDXC environment
        :param pdxc_api_url:
        :param pdxc_api_username:
        :param pdxc_api_password:
        :return: status:
        """
        logger.debug("---Inside pdxc api call for authentication---")
        status = 0
        try:
            headers = {"Content-Type": "application/json",
                       "Accept": "application/json"}
            result = requests.get(pdxc_api_url, auth=(pdxc_api_username, pdxc_api_password),
                                   headers=headers)
            if result.status_code == 200:
                status = result.status_code
            else:
                logger.error("getting error response from pdxc api with status code:{}".format(result.status_code))

        except requests.exceptions.URLRequired as e:
            logger.error("valid url is required", exc_info=True)
        except requests.exceptions.HTTPError as e:
            logger.error("HTTP error as occured", exc_info=True)
        except requests.exceptions.ConnectionError as e:
            logger.error("connection error occured", exc_info=True)
        except requests.exceptions.TooManyRedirects as e:
            logger.error("Too many redirects", exc_info=True)
        except requests.exceptions.RequestException as e:
            logger.error("There was an ambiguous exception that occurred while handling your request.", exc_info=True)
        except Exception as e:
            logger.error("Invalid pdxc events api credentials or pdxc environment", exc_info=True)
        return status

    def main():
        """This is main function which prompts for user inputs and validates them by calling respective functions"""
        DellOMECredentialCheck = "false"
        pdxcCredentialCheck = "false"
        pdxcEnvCheck = "false"
        sessid = ""
        pdxc_api_url = ""
        pdxc_environment = ""
        DellOME_ip_address = ""
        DellOMEIpAddressCheck = "false"
        DellOMESeveritiesCheck = "false"
        DellOMEStatusCheck = "false"
        Time_Frequency = "false"
        while (DellOMEIpAddressCheck == "false"):
            print("----------Provide DELLOME details----------")
            logger.debug("---Inside collecting DellOME Ip Address---")
            DellOME_ip_address = input("Enter the DellOME IP Address : ")
            status_number = DellOMEIpCheck(DellOME_ip_address)
            if (status_number == 0):
                print("You have provided invalid IP address")
                repeatDellOMEIpAddress = input("You have provided invalid IP address. Do you want to enter again (y/n) : ")
                if (repeatDellOMEIpAddress == "n" or repeatDellOMEIpAddress == "N"):
                    exit()
            else:
                configuration_file["DellOME_ip_address"] = DellOME_ip_address
                DellOMEIpAddressCheck = "true"

        while (DellOMECredentialCheck == "false"):
            print("----------Provide DellOME api credentials----------")
            logger.debug("---Inside collecting DellOME credentials---")
            DellOME_username = input("Enter the username for DellOME api access : ")
            DellOME_password = getpass.getpass(prompt='Enter the password for DellOME api access : ')
            sessid = DellOMEApiCall(DellOME_ip_address, DellOME_username, DellOME_password)
            if (sessid == ""):
                print("You have provided wrong IP address or credential ")
                repeatDellOMECredential = input("You have provided wrong IP address or credential. Do you want to enter again (y/n) : ")
                if (repeatDellOMECredential == "n" or repeatDellOMECredential == "N"):
                    exit()
            else:
                configuration_file["DellOME_username"] = DellOME_username
                encrypted_data["DellOME_password"] = encrypt_credentials(DellOME_password)
                DellOMECredentialCheck = "true"

        while (DellOMESeveritiesCheck == "false"):
            print("----------Provide DellOME tool alert severities----------")
            logger.debug("---Inside collecting DELLOME severities---")
            DellOME_severity = input("Enter the level of severity to be passed to filter alerts : ")
            resp_status = severities(DellOME_severity)
            print(resp_status)
            if (resp_status == None):
                print("You have provided invalid severities")
                repeatDellOMESeverities = input("You have provided invalid severities. Do you want to enter again (y/n) : ")
                if (repeatDellOMESeverities == "n" or repeatDellOMESeverities == "N"):
                    exit()
            else:
                resp_status = resp_status.split(",")
                response_status=[]

                for item in resp_status:
                    DictSeverity = {'info':'2', 'unknown':'1', 'critical':'16', 'warning':'8','normal':'4'}
                    severity = DictSeverity[item]
                    response_status.append(severity)
                response_status = ','.join(response_status)
                configuration_file["DellOME_severity"] = response_status
                DellOMESeveritiesCheck = "true"

        while (DellOMEStatusCheck == "false"):
            print("----------Provide DellOME tool alert status name----------")
            logger.debug("---Inside collecting DELLOME statusType---")
            DellOME_statusType = input("Enter the level of statusType to be passed to filter alerts : ")
            resp_status_type = statusType(DellOME_statusType)
            print(resp_status_type)
            if (resp_status_type == None):
                print("You have provided invalid statusType")
                repeatDellOMEStatusType = input("You have provided invalid statusType. Do you want to enter again (y/n) : ")
                if (repeatDellOMEStatusType == "n" or repeatDellOMEStatusType == "N"):
                    exit()
            else:
                resp_status_type = resp_status_type.split(',')
                response_status_type = []

                for item in resp_status_type:
                    DictStatus = {'acknowledged': '1000','not acknowledged' : '2000'}
                    status = DictStatus[item]
                    response_status_type.append(status)
                response_status_type = ','.join(response_status_type)
                configuration_file["DellOME_statusType"] = response_status_type
                DellOMEStatusCheck = "true"

        while (Time_Frequency == "false"):
            print("----------Provide  Time Frequency for fetching alerts from Dell OME tool in minutes(integer)----------")
            logger.debug("---Inside collecting timeFrequency---")
            Time_Frequency = input("Enter the Time frequency for fetching the alerts from tool:  ")
            print(Time_Frequency)
            if (Time_Frequency == None):
                print("You have provided invalid timefrequency")
                repeatDellOMETimeFrequncy = input(
                    "You have provided invalid timefrequency . Do you want to enter again (y/n) : ")
                if (repeatDellOMETimeFrequncy == "n" or repeatDellOMETimeFrequncy == "N"):
                    help('setup')
                    exit()
            else:
                configuration_file["Time_Frequency"] = Time_Frequency
                Time_Frequency = "true"

        while (pdxcEnvCheck == "false"):
            print("----------Provide PDXC API Environment----------")
            logger.debug("---Inside collecting PDXC API environment---")
            pdxc_environment = input("Enter the PDXC Environment : ")
            pdxc_environment = pdxc_environment.lower()
            url = get_util_api(pdxc_environment)
            if (url == ""):
                print("You have provided wrong environment for PDXC API")
                repeatPdxcEnv = input("You have provided wrong environment for PDXC API. Do you want to enter again (y/n) : ")
                if (repeatPdxcEnv == "n" or repeatPdxcEnv == "N"):
                    exit()
            else:
                pdxc_api_url = constructApiurl(url)
                configuration_file["pdxc_api_url_get"] = pdxc_api_url
                configuration_file["pdxc_api_url_put"] = pdxc_api_url
                pdxc_api_url_create = str(constructApiurl(url)) + suffix_create
                configuration_file["pdxc_api_url_create"] = pdxc_api_url_create
                pdxcEnvCheck = "true"

        while (pdxcCredentialCheck == "false"):
            print("----------Provide PDXC API credentials----------")
            logger.debug("---Inside collecting PDXC API credentials---")
            pdxc_api_username = input("Enter the username for PDXC API access: ")
            pdxc_api_password = getpass.getpass(prompt='Enter the password for PDXC API access: ')
            status = pdxcApiCall(pdxc_api_url, pdxc_api_username, pdxc_api_password)
            if (status == 200):
                configuration_file["pdxc_environment"] = pdxc_environment
                configuration_file["pdxc_api_username"] = pdxc_api_username
                encrypted_data["pdxc_api_password"] = encrypt_credentials(pdxc_api_password)
                combined_pdxc_api_credentials = (base64.b64encode(bytes(pdxc_api_username + ":" + pdxc_api_password,'ascii'))).decode('ascii')
                encrypted_data["combined_pdxc_api_credentials"] = encrypt_credentials(combined_pdxc_api_credentials)
                key_data["aesKey"]=base64.b64encode(key).decode('ascii')
                pdxcCredentialCheck = "true"
            else:
                repeatPdxcCredetial = input(
                    "You have provided wrong credential for PDXC API. Do you want to enter again (y/n) : ")
                if (repeatPdxcCredetial == "n" or repeatPdxcCredetial == "N"):
                    exit()
        if (True):
            with open('credentials.yaml', 'w') as cred_file:
                yaml.dump(encrypted_data, cred_file, indent=2)
            with open('init.yaml', 'w') as init_file:
                yaml.dump(configuration_file, init_file, indent=2)
            with open('aesKey.yaml', 'w') as key_file:
                yaml.dump(key_data, key_file, indent=2)
        if (DellOMEIpAddressCheck == "true" and DellOMECredentialCheck == "true" and DellOMESeveritiesCheck == "true" and DellOMEStatusCheck == "true" and pdxcEnvCheck == "true" and pdxcCredentialCheck == "true"):
            print("")
            print("Successfully created aesKey.yaml.yaml, credentials.yaml, init.yaml")

except Exception as e:
    logger.error("failed", exc_info=True)

if __name__ == '__main__':
    main()
