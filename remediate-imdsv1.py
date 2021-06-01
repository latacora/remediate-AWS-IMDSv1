import argparse
import logging
import time
import boto3
import coloredlogs

LOGGER = logging.getLogger('remediate-imdsv1')


def remediate(v1_instances, profile=None):
    """
    Takes a dict of regions & instances and enforces IMDSv2 on all instances.
    """
    LOGGER.info('Remediating instances')
    for region, instances in v1_instances.items():
        current_session = boto3.Session(profile_name=profile, region_name=region)
        client = current_session.client('ec2')
        for instance in instances:
            instance_arn = f'arn:aws:ec2:{region}:account:instance/{instance}'
            LOGGER.debug(f'Remediating {instance_arn}')
            try:
                client.modify_instance_metadata_options(
                    InstanceId=instance,
                    HttpTokens='required',
                )
            except Exception as e:
                LOGGER.error(f'Unable to remediate instance {instance_arn}: {e}')


def get_instances(profile=None):
    """
    Identifies EC2 instances with IMDSv1 enabled, returns them in a dict of regions & instances.
    """
    LOGGER.info('Identifying instances')
    session = boto3.Session(profile_name=profile)
    ec2_client = session.client('ec2')
    regions = [region['RegionName']
               for region in ec2_client.describe_regions()['Regions']]

    v1_instances = {}

    for region in regions:
        v1_instances[region] = []
        LOGGER.debug(f'Running against region {region}')
        current_session = boto3.Session(profile_name=profile, region_name=region)
        client = current_session.client('ec2')
        paginator = client.get_paginator('describe_instances')
        page_iterator = paginator.paginate(Filters=[{'Name': 'metadata-options.http-tokens',
                                                     'Values': ['optional']}])
        for page in page_iterator:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_arn = f'arn:aws:ec2:{region}:account:instance/{instance.get("InstanceId")}'
                    LOGGER.debug(f'Identified {instance_arn}')
                    v1_instances[region].append(instance.get('InstanceId'))

    return v1_instances


def run(args):
    LOGGER.info('Starting')
    v1_instances = get_instances(args.aws_profile)
    if args.is_remediation:
        remediate(v1_instances, args.aws_profile)
    LOGGER.info('Done')


if __name__ == "__main__":

    # Arguments parser
    parser = argparse.ArgumentParser(
        description='Analyze IMDSv1 usage and enforce v2.')
    parser.add_argument('-p', '--profile',
                        dest='aws_profile',
                        help='The profile with access to the desired AWS account',
                        required=False)
    parser.add_argument('-r', '--remediate',
                        dest='is_remediation',
                        help='Enforce IMDSv2 on all instances (default=False)',
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument('-d', '--debug',
                        dest='debug',
                        action='store_true',
                        help='Verbose output. Will also create a log file',
                        required=False,
                        default=False)

    args = parser.parse_args()

    if args.debug:
        fh = logging.FileHandler(f'remediate-imdsv1_debug_log-{time.strftime("%Y-%m-%d-%H%M%S")}.log')
        fh.setLevel(logging.DEBUG)
        LOGGER.addHandler(fh)
        coloredlogs.install(level='DEBUG', logger=LOGGER)
    else:
        coloredlogs.install(level='INFO', logger=LOGGER)

    try:
        session = boto3.Session(profile_name=args.aws_profile)
        sts_client = session.client("sts")
        sts_client.get_caller_identity()
    except Exception as e:
        LOGGER.error(f'Unable to authenticate: {e}')
    else:
        try:
            run(args)
        except Exception as e:
            LOGGER.error(f'Runtime exception: {e}')
