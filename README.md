# Remediate AWS IMDSv1

## Description

Simple tool to identify and remediate the use of the AWS EC2 Instance Metadata Service (IMDS) v1. For additional details, refer to the [accompanying blog post](TODO link).

## Dependencies

Setup a virtual environment and install dependencies:

```shell script
$ virtualenv -p python3 venv
$ source venv/bin/activate
$ pip -r requirements.txt
```

## Usage

View options:

```shell script
$ python remediate-imdsv1.py -h   

usage: remediate-imdsv1.py [-h] [-p AWS_PROFILE] [-r] [-d]

Analyze IMDSv1 usage and enforce v2.

optional arguments:
  -h, --help            show this help message and exit
  -p AWS_PROFILE, --profile AWS_PROFILE
                        The profile with access to the desired AWS account
  -r, --remediate       Enforce IMDSv2 on all instances (default=False)
  -d, --debug           Verbose output. Will also create a log file
```

Run:

```shell script
$ python remediate-imdsv1.py --profile <profile name> --remediate --debug

2021-05-31 16:46:51 w remediate-imdsv1[12107] INFO Starting
2021-05-31 16:46:51 w remediate-imdsv1[12107] INFO Identifying instances
2021-05-31 16:46:51 w remediate-imdsv1[12107] DEBUG Running against region us-west-2
2021-05-31 16:46:51 w remediate-imdsv1[12107] DEBUG Running against region eu-north-1
2021-05-31 16:46:52 w remediate-imdsv1[12107] DEBUG Running against region ap-south-1
2021-05-31 16:46:53 w remediate-imdsv1[12107] DEBUG Running against region eu-west-3
2021-05-31 16:46:53 w remediate-imdsv1[12107] DEBUG Running against region eu-west-2
2021-05-31 16:46:53 w remediate-imdsv1[12107] DEBUG Running against region eu-west-1
2021-05-31 16:46:53 w remediate-imdsv1[12107] DEBUG Running against region ap-northeast-3
2021-05-31 16:46:55 w remediate-imdsv1[12107] DEBUG Running against region ap-northeast-2
2021-05-31 16:46:56 w remediate-imdsv1[12107] DEBUG Running against region ap-northeast-1
2021-05-31 16:46:57 w remediate-imdsv1[12107] DEBUG Running against region sa-east-1
2021-05-31 16:46:59 w remediate-imdsv1[12107] DEBUG Running against region ca-central-1
2021-05-31 16:46:59 w remediate-imdsv1[12107] DEBUG Running against region ap-southeast-1
2021-05-31 16:47:00 w remediate-imdsv1[12107] DEBUG Running against region ap-southeast-2
2021-05-31 16:47:02 w remediate-imdsv1[12107] DEBUG Running against region eu-central-1
2021-05-31 16:47:02 w remediate-imdsv1[12107] DEBUG Running against region us-east-1
2021-05-31 16:47:02 w remediate-imdsv1[12107] DEBUG Identified arn:aws:ec2:us-east-1:account:instance/i-1234567890
2021-05-31 16:47:03 w remediate-imdsv1[12107] DEBUG Running against region us-east-2
2021-05-31 16:47:04 w remediate-imdsv1[12107] DEBUG Running against region us-west-1
2021-05-31 16:47:05 w remediate-imdsv1[12107] DEBUG Running against region us-west-2
2021-05-31 16:47:06 w remediate-imdsv1[12107] INFO Remediating instances
2021-05-31 16:47:06 w remediate-imdsv1[12107] DEBUG Remediating arn:aws:ec2:us-east-1:account:instance/i-1234567890
2021-05-31 16:47:09 w remediate-imdsv1[12107] INFO Done
```