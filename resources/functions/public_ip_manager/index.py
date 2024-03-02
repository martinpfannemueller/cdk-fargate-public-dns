import os
import boto3

assumed_role = os.environ.get("DNS_ASSUMED_ROLE")
hosted_zone = os.environ.get("DNS_HOSTED_ZONE")
domain_name = os.environ.get("DNS_DOMAIN")

if not domain_name:
    raise Exception("DNS_DOMAIN environment variable must be set")
if not hosted_zone:
    raise Exception("DNS_HOSTED_ZONE environment variable must be set")


def find_eni_id(event):
    attachments = event["detail"]["attachments"]
    for attachment in attachments:
        if attachment["type"] == "eni" and attachment["status"] == "ATTACHED":
            for detail in attachment["details"]:
                if detail["name"] == "networkInterfaceId":
                    return detail["value"]

    raise Exception("Unable to locate attached ENI")


def update_dns(public_ipv4, public_ipv6, hosted_zone, domain_name, assumed_role=None):

    r53 = boto3.client("route53")

    if assumed_role:
        sts = boto3.client("sts")
        sts_response = sts.assume_role(
            RoleArn=assumed_role, RoleSessionName="cdk-fargate-public-dns"
        )

        credentials = sts_response["Credentials"]

        r53 = boto3.client(
            "route53",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

    r53.change_resource_record_sets(
        HostedZoneId=hosted_zone,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": domain_name,
                        "Type": "A",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": public_ipv4}],
                    },
                }
            ]
        },
    )

    r53.change_resource_record_sets(
        HostedZoneId=hosted_zone,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": domain_name,
                        "Type": "AAAA",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": public_ipv6}],
                    },
                }
            ]
        },
    )


def handler(event, context):

    eni_id = find_eni_id(event)

    ec2 = boto3.resource("ec2")
    eni = ec2.NetworkInterface(eni_id)
    public_ipv4 = eni.association_attribute["PublicIp"]
    public_ipv6 = eni.ipv6_address

    update_dns(public_ipv4, public_ipv6, hosted_zone, domain_name, assumed_role)

    return True
