"""
#for any help related with this script execute help('Invoke') on python console.

SYNOPSIS:
This is a Invoke script which creates incidents from hardware monitoring events through Dell OME to PDXC
Original creation date: March 2020
Version:1.0
Team:DTC_pDXCsquad1
DL:DTC_BLR_pDXCSquad@dxc.com

DESCRIPTION:
This script will take initialization parameters and encrypted user access passwords from init.yaml and credentials.yaml respectively.
It will create the incidents from monitoring events through HP OneView to PDXC and also synchronises incident and event status in PDXC and HP OneView.

EXAMPLE:
py invoke.py

OUTPUT:
Creates a incident for each hardware monitoring event.
Synchronises incident and event status in PDXC and HP OneView.

"""
import json
import requests
from pprint import pprint
import time
import datetime
import base64
import urllib3
import threading
import yaml
import logging
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')
file_handler = logging.FileHandler('Invoke.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
max_tries = 4
tries = 0
try:

    def getKey(key):
        """
        This function fetches base64 encoded key from aesKey.yaml
        :param key:
        :return: encodedKey
        """
        logger.debug("---Inside get Key---")
        with open('aesKey.yaml') as q:
            keyData = yaml.load(q, Loader=yaml.FullLoader)
            encodedKey = keyData[key]
        return encodedKey

    def getInfo(infoKey):
        """
        This function passes stored values in credential.yaml and init.yaml to Invoke script
        :param credentialKey:
        :return: credential if matches key values in init.yaml
        :return: credential if matches key values in credential.yaml
        """
        logger.debug("---Inside get Info---")
        with open('init.yaml') as q:
            credentialsData = yaml.load(q, Loader=yaml.FullLoader)
            credential = credentialsData[infoKey]
        return credential

    def getDecryptedCredential(encryptedCredentialKey):
        """
        This function decrypts credentials stored in credential.yaml file
        :param encryptedCredentialKey:
        :return: decryptedCredential
        """
        logger.debug("---Inside get DecryptedCredential---")
        get_key = getKey("aesKey")
        decodedKey = base64.b64decode(bytes(get_key, 'ascii'))
        with open('credentials.yaml') as q:
            credentialsData = yaml.load(q, Loader=yaml.FullLoader)
            encodedCredential = credentialsData[encryptedCredentialKey]
            base64Credential = encodedCredential
            base64Bytes = base64Credential.encode('ascii')
            credentialBytes = base64.b64decode(base64Bytes)
            iv = credentialBytes[:16]
            hiddenMessage = credentialBytes[16:]
            cipher = AES.new(decodedKey, AES.MODE_CFB, iv)
            decryptedCredentialBytes = cipher.decrypt(hiddenMessage)
            decryptedCredential = decryptedCredentialBytes.decode('ascii')
        return decryptedCredential

    def getUrlForAlert(DellOME_ip_address):
        """
        This function construct the url based on severity type,status type,timestamp passed from DellOME console
        :param DellOME_ip_address:
        :return: construct_url
        """
        logger.debug("---Inside getUrlForAlert---")
        severities = str(getInfo("DellOME_severity")).split(",")
        statustype = str(getInfo("DellOME_statusType")).split(",")
        Time_Frequency =int(getInfo("Time_Frequency"))
        current_time = datetime.datetime.now()
        fetch_alert_begin_time= datetime.datetime.now() -datetime.timedelta(minutes=Time_Frequency)
        urlforalerts = ""
        construct_url= ""
        urlforalerts = "https://" + DellOME_ip_address + "/api/AlertService/Alerts?$filter=SeverityType eq {}".format(severities[0])
        severityTypeCheck = " or SeverityType eq {}"
        for i in range(len(severities) - 1):
            urlforalerts = urlforalerts + severityTypeCheck
            urlforalerts = urlforalerts.replace('{}', severities[i + 1])
        condition_before_statusType = " and StatusType eq {}".format(statustype[0])
        statusTypeCheck = " or StatusType eq {}"
        time_Stamp_Begin = " and TimeStamp ge '{}'".format(fetch_alert_begin_time)
        time_Stamp_End = " and TimeStamp le '{}'".format(current_time)

        for j in range(len(statustype) - 1):
            condition_before_statusType = condition_before_statusType + statusTypeCheck
            condition_before_statusType = condition_before_statusType.replace('{}', statustype[j + 1])
        construct_url = urlforalerts + condition_before_statusType
        construct_url = construct_url + time_Stamp_Begin + time_Stamp_End
        print(construct_url)
        return (construct_url)

    def getAlertList(DellOMEipaddress):
        """
        This function calling getUrlForAlert(DellOME_ip_address)and fetches alert list from DellOME console
        :param DellOMEipaddress
        :return: alertList
        """
        logger.debug("---Inside getAlertList---")
        alertList = ""
        tries = 0
        while (alertList == ""):
            tries = tries + 1
            if (tries < max_tries):
                try:
                    result = ""
                    urlforalerts = str(getUrlForAlert(DellOMEipaddress))

                    base_url = 'https://%s' % DellOMEipaddress
                    session_url = base_url + "/api/SessionService/Sessions"

                    header = {"Content-Type": "application/json"}
                    user_details = {'UserName': str(getInfo("DellOME_username")),
                                    'Password': str(getDecryptedCredential("DellOME_password")),
                                    'SessionType': 'API'}

                    session_info = requests.post(session_url, verify=False,
                                                 data=json.dumps(user_details),
                                                 headers=header)

                    if session_info.status_code == 201:
                        header['X-Auth-Token'] = session_info.headers['X-Auth-Token']
                        result = requests.get(urlforalerts, headers=header, verify=False)
                        if result.status_code == 200:
                             alertList = result.json()
                        else:
                            logger.error("getting error response from Dell Ome alertList with status code:{}".format(result.status_code))
                    else:
                         logger.error("getting error response from Dell Ome with status code:{}".format(session_info.status_code))
                except requests.exceptions.URLRequired as e:
                         logger.error("valid url is required", exc_info=True)
                except requests.exceptions.HTTPError as e:
                    logger.error("HTTP error as occured", exc_info=True)
                except requests.exceptions.ConnectionError as e:
                    logger.error("connection error occured", exc_info=True)
                except requests.exceptions.TooManyRedirects as e:
                    logger.error("Too many redirects", exc_info=True)
                except requests.exceptions.RequestException as e:
                    logger.error("There was an ambiguous exception that occurred while handling your request.",exc_info=True)
                except Exception as e:
                    logger.error("Falied to get Alert List", exc_info=True)
            else:
                break
        return alertList

    def getCreateIncidentReqBody(alertList):
        """
        This function creates required incident body to be passed as payload to PDXC API
        :param alertList:
        :return: body_pdxc_api
        """
        body_pdxc_api = []
        logger.debug("---Inside create incident request body---")

        for item in alertList["value"]:
            AlertDeviceName = item["AlertDeviceName"]
            Message =item["Message"]
            severity = item["SeverityName"]
            servername = item["AlertDeviceName"]
            createdtime = item["TimeStamp"]
            alertid = item["AlertMessageId"]
            alertDetails = ""
            Id = item["Id"]
            AlertDeviceIpAddress =  item["AlertDeviceIpAddress"]
            AlertDeviceMacAddress =  item["AlertDeviceMacAddress"]
            AlertDeviceIdentifier =  item["AlertDeviceIdentifier"]
            CategoryId =  item["CategoryId"]
            CatalogName=item["CatalogName"]
            CategoryName =  item["CategoryName"]
            SubCategoryName =  item["SubCategoryName"]
            StatusType =  item["StatusType"]
            StatusName = item["StatusName"]
            TimeStamp = item["TimeStamp"]
            Message = item["Message"]
            EemiMessage = item["EemiMessage"]
            RecommendedAction =  item["RecommendedAction"]
            AlertMessageId =  item["AlertMessageId"]
            AlertMessageType =  item["AlertMessageType"]

            alertDetails = "serverhardwareDetails= " + " CategoryId:" + str(CategoryId) + ",CatalogName:" + str(CatalogName) + ", CategoryName:" + str(
                CategoryName) + ",TimeStamp:" + str(TimeStamp) + ",SeverityName:" + str(
                severity) + ",SubCategoryName:" + str(
                SubCategoryName) + ",StatusName:" + str(StatusName) + ",Message:" + str(
                Message) + ",EemiMessage:" + str(EemiMessage) + ",StatusType:" + str(
                StatusType) + ",AlertDeviceIpAddress:" + str(AlertDeviceIpAddress) + ",AlertDeviceMacAddress:" + str(AlertDeviceMacAddress) + ",AlertDeviceIdentifier:" + str(
                AlertDeviceIdentifier) + ",Id:" + str(Id) + ",AlertMessageId:" + str(AlertMessageId) + ",AlertMessageType:" + str(AlertMessageType)
            action = str(RecommendedAction) + alertDetails
            description = Message +"AlertDeviceName:"+ str(AlertDeviceName)

            #t = datetime.datetime.now()
            Dict = {'Info': 'Normal', 'Unknown': 'Normal', 'Critical': 'Critical', 'Warning': 'Warning','Normal': 'Normal'}
            pdxc_severity = Dict[severity]
            body = {
             "EventList": [
                {
                    "severity": pdxc_severity,

                    "title": description,
                    "longDescription": action,
                    "node": "",
                    "relatedcihints": "",
                    "eventsourcesendingserver": servername,
                    "eventsourceexternalid": alertid,
                    "eventsourcecreatedtime": createdtime,
                    "category": "solarwinds_sam",
                    "incidentCategory": "Hardware",
                    "application": "Myapps",
                    "object": "MyObject",
                }]}

            body_pdxc_api.append(body)
        return body_pdxc_api

    def createIncident(body):
        """
        This function creates required incident body to be passed as payload to PDXC API
        :param body:
        :return uuid:
        """
        logger.debug("---Inside create incident---")
        uuid = ""
        tries = 0
        while (uuid == ""):
            tries = tries + 1
            if (tries < max_tries):
                try:
                    urlforcreateincident = str(getInfo("pdxc_api_url_create"))
                    header_pdxc_url = {"Content-Type": "application/json"}
                    output = requests.post(urlforcreateincident, auth=(getInfo("pdxc_api_username"),getDecryptedCredential("pdxc_api_password")), headers=header_pdxc_url, data=json.dumps(body))
                    data = output.json()
                    pprint(data)
                    for item in data:
                        uuid = item["uuid"]
                except requests.exceptions.URLRequired as e:
                        logger.error("valid url is required", exc_info=True)
                except requests.exceptions.HTTPError as e:
                    logger.error("HTTP error as occured", exc_info=True)
                except requests.exceptions.ConnectionError as e:
                    logger.error("connection error occured", exc_info=True)
                except requests.exceptions.TooManyRedirects as e:
                    logger.error("Too many redirects", exc_info=True)
                except requests.exceptions.RequestException as e:
                    logger.error("There was an ambiguous exception that occurred while handling your request.",exc_info=True)
                except Exception as e:
                    logger.error("failed to create incident", exc_info=True)
            else:
                break
        return uuid

    def main():
        """
        This is a main function
        :return:
        """
        logger.debug("---Inside main---")
        DellOMEipaddress = getInfo("DellOME_ip_address")
        alertList = getAlertList(DellOMEipaddress)
        if (alertList == ""):
            logger.debug("unable to get alert list, so skipping the task")
            return
        createIncidentBody = getCreateIncidentReqBody(alertList)
        uuids = []
        for item in createIncidentBody:
            uuid = createIncident(item)
            uuids.append(uuid)
        logger.debug(uuids)

    main()
except Exception as e:
    logger.error("failed", exc_info=True)
