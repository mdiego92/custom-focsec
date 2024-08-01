#!/usr/bin/env python3
##### custom-focsec
# Author: Sakugawa Diego
# Version: 2024.07.10
# Description:
# 
# Wazuh integration that allows analyzing IP addresses from rules
# with Focsec to identify if they are associated with a VPN, Proxy, TOR,
# or malicious bots.
#
# Configuration examples:
#
#  <integration>
#      <name>custom-focsec</name>
#      <hook_url>https://api.focsec.com/v1/ip/</hook_url>
#      <api_key>...</api_key>
#      <rule_id>5760</rule_id>
#      <alert_format>json</alert_format>
#  </integration>
#
#  <integration>
#      <name>custom-focsec</name>
#      <hook_url>https://api.focsec.com/v1/ip/</hook_url>
#      <api_key>...</api_key>
#      <group>attacks</group>
#      <alert_format>json</alert_format>
#  </integration>
#
#############################

import sys
import json
import requests
import socket
from os import path
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Import utils from wodles
sys.path.insert(0, path.join(path.dirname(path.dirname(path.abspath(__file__))), 'wodles'))
import utils

# Global debug level
debug_level = 0

def main(argv):
    global debug_level

    if len(argv) < 3:
        logger.error("Insufficient arguments provided. Expected at least 3.")
        sys.exit(1)

    # Set debug level
    if len(argv) > 3 and argv[3].lower() == 'debug':
        debug_level = 1
        argv = argv[:3]
    else:
        debug_level = 0

    logger.debug(f"Raw arguments: {argv}")
    logger.debug(f"Debug mode on - Level: {debug_level}")

    # Read configuration parameters
    alert_file_path = argv[0]
    api_key = argv[1]
    hook_url = argv[2]

    logger.debug(f"Alert file path: {alert_file_path}")
    logger.debug(f"API key: {api_key}")
    logger.debug(f"Hook URL: {hook_url}")

    try:
        # Read the alert file
        with open(alert_file_path) as alert_file:
            alert_json = json.load(alert_file)
        logger.debug(f"Alert JSON: {alert_json}")

        # Extract information from the alert
        ip_address = alert_json['data']['srcip']
        srcport = alert_json['data']['srcport']
        dstuser = alert_json['data']['dstuser']
        agent_id = alert_json['agent']['id']
        agent_name = alert_json['agent']['name']
        original_timestamp = alert_json['predecoder']['timestamp']
        ruleid = alert_json['rule']['id']
        description = alert_json['rule']['description']

        # Create the API request URL
        api_url = f"{hook_url}{ip_address}?api_key={api_key}"
        logger.debug(f"API URL: {api_url}")

        # Make the API request
        response = requests.get(api_url)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Text: {response.text}")
        response.raise_for_status()
        api_data = response.json()

        # Combine API response with additional data
        combined_data = {
            **api_data,
            "srcip": ip_address,
            "srcport": srcport,
            "dstuser": dstuser,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "original_timestamp": original_timestamp,
            "integration": "focsec",
            "triggered_by_rule": f"{ruleid} {description}"
        }

        # Send the data to the Wazuh queue
        send_msg(combined_data)

    except requests.HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
        sys.exit(12)
    except requests.RequestException as req_err:
        logger.error(f"Request exception occurred: {req_err}")
        sys.exit(14)
    except Exception as err:
        logger.error(f"General error occurred: {err}")
        sys.exit(15)

def send_msg(msg):
    """Sends an event to the Wazuh Queue.

    Args:
        msg (dict): The message to send, formatted as a JSON-serializable dictionary.

    Raises:
        socket.error: If there is an issue with the socket connection.
        Exception: For other general errors.
    """
    try:
        json_msg = json.dumps(msg, default=str)
        logger.debug(f"Message to send: {json_msg}")
        wazuh_queue = path.join(utils.find_wazuh_path(), 'queue/sockets/queue')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(wazuh_queue)
            msg_header = "1:Wazuh-focsec:"
            s.send(f"{msg_header}{json_msg}".encode())
    except socket.error as e:
        if e.errno == 111:
            logger.error("Wazuh must be running.")
            sys.exit(11)
        elif e.errno == 90:
            logger.error("Message too long to send to Wazuh. Skipping message...")
            sys.exit(16)
        else:
            logger.error(f"Error sending message to Wazuh: {e}")
            sys.exit(13)
    except Exception as e:
        logger.error(f"General error sending message to Wazuh: {e}")
        sys.exit(13)

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unknown error: {e}")
        if debug_level > 0:
            raise
        sys.exit(1)

