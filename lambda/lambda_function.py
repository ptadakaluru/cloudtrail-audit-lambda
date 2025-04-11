import boto3
import datetime
import botocore.exceptions
import json
import os
import requests

sns = boto3.client('sns')
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")
WHITELISTED_REGIONS = set(os.environ.get("WHITELISTED_REGIONS", "").split(","))
HOURS_BACK = int(os.environ.get("HOURS_BACK", 1))

SKIP_SERVICES = {'cloudtrail', 'sts', 'signin'}

def get_geolocation(ip):
    try:
        if ip == 'UNKNOWN' or ip.startswith("127.") or ip.startswith("::1") or ip.startswith("169.254"):
            return {"country": "LOCAL", "region": "LOCAL", "city": "LOCAL"}
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = response.json()
        return {
            "country": data.get("country_name", "UNKNOWN"),
            "region": data.get("region", "UNKNOWN"),
            "city": data.get("city", "UNKNOWN")
        }
    except Exception as e:
        print(f"[GeoIP Error] IP: {ip}, Error: {str(e)}")
        return {"country": "UNKNOWN", "region": "UNKNOWN", "city": "UNKNOWN"}

def lambda_handler(event, context):
    now = datetime.datetime.utcnow()
    start_time = now - datetime.timedelta(hours=HOURS_BACK)

    ec2 = boto3.client('ec2')
    regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    region_service_usage = {}

    for region in regions:
        try:
            print(f"Scanning region: {region}")
            ct = boto3.client('cloudtrail', region_name=region)
            paginator = ct.get_paginator('lookup_events')
            page_iterator = paginator.paginate(StartTime=start_time)

            for page in page_iterator:
                for event in page.get('Events', []):
                    event_source = event.get('EventSource', '')
                    username = event.get('Username', 'UNKNOWN')
                    event_name = event.get('EventName', 'UNKNOWN')
                    raw_event = event.get('CloudTrailEvent')

                    try:
                        parsed_event = json.loads(raw_event)
                        event_time = parsed_event.get('eventTime', 'UNKNOWN')
                        source_ip = parsed_event.get('sourceIPAddress', 'UNKNOWN')
                        user_agent = parsed_event.get('userAgent', 'UNKNOWN')
                    except Exception:
                        event_time = source_ip = user_agent = 'UNKNOWN'

                    service = event_source.replace('.amazonaws.com', '')

                    if (
                        service not in SKIP_SERVICES and
                        not username.startswith("TrustedAdvisor")
                    ):
                        region_service_usage.setdefault(region, {})
                        if service not in region_service_usage[region]:
                            geo = get_geolocation(source_ip)
                            region_service_usage[region][service] = {
                                "username": username,
                                "eventName": event_name,
                                "eventTime": event_time,
                                "sourceIP": source_ip,
                                "userAgent": user_agent,
                                "geoLocation": geo
                            }

        except botocore.exceptions.ClientError as e:
            print(f"[ERROR] in region {region}: {str(e)}")
        except botocore.exceptions.EndpointConnectionError:
            print(f"[SKIP] Region {region} not reachable.")

    flagged = {
        region: services
        for region, services in region_service_usage.items()
        if services and region not in WHITELISTED_REGIONS
    }

    if flagged and ALERT_TOPIC_ARN:
        msg = f"Non-whitelisted AWS regions were accessed:\n\n"
        for region, services in flagged.items():
            msg += f"🔸 {region}:\n"
            for svc, details in services.items():
                msg += f"  - {svc} used by {details['username']} (event: {details['eventName']}) at {details['eventTime']} from {details['sourceIP']} ({details['geoLocation']['country']}, {details['geoLocation']['city']})\n"
        sns.publish(
            TopicArn=ALERT_TOPIC_ARN,
            Subject="⚠️ CloudTrail Alert: Unauthorized Region Activity",
            Message=msg
        )

    return {
        "statusCode": 200,
        "hours_scanned": HOURS_BACK,
        "non_whitelisted_regions": sorted(list(flagged.keys())),
        "flagged_services": flagged
    }

