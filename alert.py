#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import requests

WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR URL XD"  # Put Your Webhook Url xd
IP_THRESHOLD = 10  # Send an alert for each IP every 50 seconds
counter = 0
ip_log = {}

def send_to_discord(ip_events):
    # Create the Discord message data
    data = {
        "content": f":shield: Suricata LOGS \n\n"
                   f"Live Logs: \n",
        "username": "Suricata (LOGS)",  # Webhook Name
        "avatar_url": "https://imgur.com/5KXvYZo",  # avatar
        "embeds": []
    }

    # Create an embed for each destination IP
    for ip, events in ip_events.items():
        fields = []
        # Show only the last 4 events for each IP
        for event in events[-4:]:
            alert = event['alert']['signature']
            dest_ip = event['dest_ip']
            dest_port = event['dest_port']
            protocol = event['proto']
            timestamp = event['timestamp']
            #paquets = event['flow']
            fields.append({
                "name": f":Warning: Detected anomaly Possible Attack ",
                "value": f"  **Server IP:** {dest_ip} | **Port:** {dest_port} |**Alert**: {alert}| **Protocol:** {protocol}| **Timestamp:** {timestamp}",
                "inline": False
            })

        embed = {
            "title": f"Destination IP: {dest_ip}",
            "color": 0xff0000,
            "fields": fields
        }
        data["embeds"].append(embed)

    headers = {"Content-Type": "application/json"}
    response = requests.post(WEBHOOK_URL, json=data, headers=headers)
    if response.status_code == 200:
        print(f"Message sent successfully")
    else:
        print(f"Error sending message: {response.status_code} {response.reason}")

while True:
    with open("/path/to/eve.json", "r") as f: # CHANGE THIS TO YOU eve.json PATH
        for line in f:
            log = json.loads(line.strip())

            # Check if the log contains the necessary information for an alert
            if "alert" in log and "dest_ip" in log and "dest_port" in log and "proto" in log:
                dest_ip = log['dest_ip']

                # Check if the destination IP starts with 'Your ip range'
                if not dest_ip.startswith('Your own IP Range'):    # Put your ip range xd like this 89.234.12
                    continue

                # If this is the first log for this IP, add it to the log dictionary
                if dest_ip not in ip_log:
                    ip_log[dest_ip] = {"events": [log], "last_sent": time.time()}
                else:
                    ip_log[dest_ip]["events"].append(log)

        # Send an alert for each IP if 50 seconds have passed since the last one
        for ip, data in ip_log.items():
            if time.time() - data["last_sent"] >= IP_THRESHOLD:
                events = data["events"][-4:]
                events.sort(key=lambda x: x['timestamp'])
                send_to_discord({ip: events})
                data["last_sent"] = time.time()
                ip_log[ip] = data

    time.sleep(1)
