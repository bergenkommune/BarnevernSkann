# Copyright (C) 2023 Bergen Kommune
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import sys
import jwt
import os
import requests
import secrets
import base64
import shutil
from datetime import datetime, timezone, timedelta

configFile = open('config.json', 'r')  # get config
config = json.loads(configFile.read())

workingDirectory = str(config['workingDirectory'])  # directory where scanned documents are found
privateKeyFile = str(config['privateKeyFile'])  # private key file


def readkey(fk):  # read private key function
    with open(fk, 'r') as f:
        return f.read()


def log():  # logger creator/append function
    loggerDate = datetime.strftime(datetime.now(), '%Y-%m-%d')
    f = open(workingDirectory + 'Logs/' + loggerDate + '.log', 'a+')
    return f


def userformatcheck(userName):  # username format validator function
    return userName.isalnum() and not userName.isalpha() and not userName.isdigit()


def maskinporttokenpostrequest():  # creates JWT and requests access token from Maskinporten
    iat = datetime.now(tz=timezone.utc)
    exp = datetime.now(tz=timezone.utc) + timedelta(seconds=int(config['timeout']))

    mportHeader = {  # Maskinporten header constructor
        "alg": "RS256",
        "kid": str(config['maskinportenKid'])  # KID is required if JWK is registered in Maskinporten
    }

    jti = (str(secrets.token_hex(4)) + '-' + str(secrets.token_hex(2)) + '-' + str(secrets.token_hex(2)) +
           '-' + str(secrets.token_hex(2)) + '-' + str(secrets.token_hex(6)))  # create unique JTI for every request

    mportPayload = {  # Maskinporten payload constructor
        "aud": str(config['maskinportenUrl']),
        "scope": str(config['maskinportenScope']),
        "iss": str(config['maskinportenIssuer']),
        "exp": int(datetime.timestamp(exp)),
        "iat": int(datetime.timestamp(iat)),
        "jti": jti
    }

    privateKey = readkey(privateKeyFile)

    token = jwt.encode(payload=mportPayload, key=privateKey, algorithm='RS256', headers=mportHeader)  # make the JWT

    session = requests.Session()  # new requests session

    r = session.post(str(config['maskinportenUrl']) + 'token',  # post request to Maskinporten
                     headers={'content-type': 'application/x-www-form-urlencoded'},
                     data=('grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + str(token)))
    r.close()
    print(r.json())
    print(r.status_code)
    if r.status_code == 200:  # success, return answer
        return r.json()
    else:  # return response and json content as list for error handling
        return [r.status_code, r.json()]


def apimoduluspostrequest(token, doc, district, fileName):  # push data to api with post-request
    if userformatcheck(fileName[0:5]):  # if username fits Bergen format, change to whatever format you use
        request_body = {'title': 'Skannet ' + str(fileName), 'unit': district, 'note': 'Skannet dokument',
                       'scannedBy': fileName[0:5], 'documents': doc}
        header = {'user-agent': 'BarnevernSkann/1.0.1', 'Accept': 'application/json',
                  'Authorization': f'Bearer {token}'}
    else:  # else unknown user
        request_body = {'title': 'Skannet ' + str(fileName), 'unit': district, 'note': 'Skannet dokument',
                       'scannedBy': 'Ukjent', 'documents': doc}
        header = {'user-agent': 'BarnevernSkann/1.0.1', 'Accept': 'application/json',
                  'Authorization': f'Bearer {token}'}

    session = requests.Session()  # new requests session

    print(header)

    r = session.post(str(config['modulusUrl']) + 'external-api/v1/mailing', headers=header, json=request_body,
                     allow_redirects=False)  # post request to Modulus api
    r.close()

    print(r.text)

    if r.status_code == 204:  # response status code handling, api doesn't return json content if 204 success
        return {'code': '204'}
    else:  # return response json content for error handling
        return r.json()


if __name__ == '__main__':
    dirsList = []
    for dirs in os.scandir(workingDirectory):  # checking if directories Logs, Finished and Failed exists
        if dirs.is_dir():
            dirsList.append(str(dirs.name))

    if 'Logs' not in dirsList:  # if they do not exist, create them
        os.mkdir(workingDirectory + 'Logs')
    if 'Finished' not in dirsList:
        os.mkdir(workingDirectory + 'Finished')
    if 'Failed' not in dirsList:
        os.mkdir(workingDirectory + 'Failed')

    logger = log()  # generate logger and create/open logfile
    currentTime = datetime.now()
    logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') + ' - Starting uploads...\n')

    maskinToken = maskinporttokenpostrequest()  # request Maskinporten token

    if isinstance(maskinToken, list):  # failed to get token due to HTTP error
        logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                     ' - Maskinporten token request failed with error: ' + str(maskinToken) + '\n')
        logger.close()
        sys.exit(-1)  # exit with error code, no point in trying if token can't be requested

    else:  # working token received, going through directories and sending files
        for dirs in os.scandir(workingDirectory):

            # making sure we don't upload files from Failed, Finished and Logs directories
            if str(dirs.name) != 'Failed' and str(dirs.name) != 'Finished' and str(dirs.name) != 'Logs':

                for file in os.scandir(dirs.path):  # getting each file in the folder
                    if file.is_file() and 'pdf' in file.name:
                        currentTime = datetime.now()

                        try:  # preventing potential OSErrors from stopping upload
                            scanFile = open(str(file.path), 'rb')
                            yay = scanFile.read()
                            scanFile.close()

                            document = [
                                {'title': str(file.name), 'mimeType': 'application/pdf',
                                 'file': base64.b64encode(yay).decode()}]  # only PDFs are accepted, b64 encode the file

                            # attempt initial post request, get response as an object for further handling
                            response = apimoduluspostrequest(maskinToken['access_token'],
                                                             document, str(dirs.name), str(file.name))

                            # handle the api response here
                            if response['code'] == '204':  # log success, move to finished
                                shutil.move(file.path, str(workingDirectory + 'Finished/' + file.name))
                                logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                                             ' - ' + str(file.name) + ' successfully uploaded: ' + str(response) + '\n')

                            elif response['code'] == '400':  # log missing fields, move to failed
                                shutil.move(file.path, str(workingDirectory + 'Failed/' + file.name))
                                logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                                             ' - ' + str(file.name) + ' failed with error: ' + str(response) + '\n')

                            elif response['code'] == '403':  # log invalid token, get new token and try again
                                maskinToken = maskinporttokenpostrequest()
                                nextResponse = apimoduluspostrequest(maskinToken['access_token'],
                                                                     document, str(dirs.name), str(file.name))
                                logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                                             ' - Maskinporten token expired, retrying...\n')

                                if nextResponse['code'] == '204':  # log success, move to finished
                                    shutil.move(file.path, str(workingDirectory + 'Finished/' + file.name))
                                    logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                                                 ' - ' + str(file.name) + ' successfully uploaded: ' + str(
                                        response) + '\n')

                                else:  # log failed, moved to failed
                                    shutil.move(file.path, str(workingDirectory + 'Failed/' + file.name))
                                    logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                                                 ' - ' + str(file.name) + ' failed with error: ' + str(response) + '\n')

                            else:  # handle any other potential errors
                                logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                                             ' - ' + str(file.name) + ' failed with error: ' + str(response) + '\n')
                                logger.close()
                                sys.exit(-1)  # exiting, no point retrying if HTTP errors prevent communication

                        except OSError as e:
                            logger.write(datetime.strftime(currentTime, '%Y-%m-%d %H:%M:%S') +
                                         ' - ' + str(file.name) + ' failed with error: ' + str(e) + '\n')

        logger.write(datetime.strftime(datetime.now(), '%Y-%m-%d %H:%M:%S') + ' - Uploads done!')
        logger.close()
        sys.exit(0)
