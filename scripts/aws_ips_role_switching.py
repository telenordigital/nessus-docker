import boto3
from collections import defaultdict

"""
A tool for retrieving all Public IPs that can be scanned by Nessus Vulnerability Manager.
- Obtain all Public IPs filtering out 'm1.small', 't1.micro', 't2.nano' instance types.
To run this tool, AWS CLI is required, with API access keys for the AWS account in ~/.aws/credentials
To run this rool with aws-vault: aws-vault exec payment-cc -- python aws_ips_nessus.py
"""

not_scanned = ['m1.small', 't1.micro', 't2.nano'] # AWS doesn't allow the scanning of specific instances
attributes = ['Name', 'Type', 'State', 'InstanceID', 'Private IP', 'Public IP', 'Launch Time']


# Connect to the EC2 module and create's a dictionary for ec2 instance data
def connect():
    ec2 = boto3.resource('ec2')
    # Get information for all running instances
    running_instances = ec2.instances.filter(Filters=[{
        'Name': 'instance-state-name',
        'Values': ['running']}])
    ec2info = defaultdict()
    for instance in running_instances:
        for tag in instance.tags:
            if 'Name' in tag['Key']:
                name = tag['Value']
        # Add instance info to a dictionary
        ec2info[instance.id] = {
            'Name': name,
            'Type': instance.instance_type,
            'State': instance.state['Name'],
            'InstanceID': instance.id,
            'Private IP': instance.private_ip_address,
            'Public IP': instance.public_ip_address,
            'Launch Time': instance.launch_time
            }
    return ec2info


def public_ips(ec2info):

    pub_ips = 0
    pub_ips_list = []
    pub_ips_not_scanned = 0
    pub_ips_not_scanned_list = []

    # identifies public ips for scanning
    for instance_id, instance in ec2info.items():
        if not instance['Type'] in not_scanned and instance['Public IP'] != None:
            pub_ips_list.append(instance['Public IP'])
            pub_ips += 1

    for instance_id, instance in ec2info.items():
        if instance['Type'] in not_scanned and instance['Public IP'] != None:
            pub_ips_not_scanned_list.append(instance['Public IP'])
            pub_ips_not_scanned += 1

    print("--1.0----PUBLIC IPs for nessus scanning [list]-----")
    print pub_ips, "Total IPs"
    print '[%s]' % ', '.join(map(str, pub_ips_list))
    print "\n"


    print("--1.1----PUBLIC IPs - NOT SCANNED-----")
    print pub_ips_not_scanned, "Total IPs"
    print '[%s]' % ', '.join(map(str, pub_ips_not_scanned_list))
    print "\n"


def public_ips_details(ec2info):

    print("--1.0----PUBLIC IPs - Details-----")
    for instance_id, instance in ec2info.items():
        if not instance['Type'] in not_scanned and instance['Public IP'] != None:
            for key in attributes:
                print("{0}: {1}".format(key, instance[key]))
            print("------")
    print "\n"

    print("--1.1----PUBLIC IPs  - NOT SCANNED - Details-----")

    for instance_id, instance in ec2info.items():
        if instance['Type'] in not_scanned and instance['Public IP'] != None:
            for key in attributes:
                print("{0}: {1}".format(key, instance[key]))
            print("------")
    print "\n"



def private_ips(ec2info):

    priv_ips = 0
    priv_ips_list = []
    priv_ips_not_scanned = 0
    priv_ips_not_scanned_list = []

    for instance_id, instance in ec2info.items():
        if not instance['Type'] in not_scanned and instance['Private IP'] != None:
            priv_ips_list.append(instance['Private IP'])
            priv_ips += 1

    for instance_id, instance in ec2info.items():
        if instance['Type'] in not_scanned and instance['Private IP'] != None:
            priv_ips_not_scanned_list.append(instance['Private IP'])
            priv_ips_not_scanned += 1

    print("--2.0----PRIVATE IPs for nessus scanning [list]-----")
    print priv_ips, "Total IPs"
    print '[%s]' % ', '.join(map(str, priv_ips_list))
    print "\n"


    print("--2.1----PRIVATE IPs - NOT SCANNED-----")
    print priv_ips_not_scanned, "Total IPs"
    print '[%s]' % ', '.join(map(str, priv_ips_not_scanned_list))
    print "\n"




def private_ips_details(ec2info):

    print("--2.0----PRIVATE IPs - Details-----")
    for instance_id, instance in ec2info.items():
        if not instance['Type'] in not_scanned and instance['Private IP'] != None:
            for key in attributes:
                print("{0}: {1}".format(key, instance[key]))
            print("------")
    print "\n"

    print("--2.1----PRIVATE IPs  - NOT SCANNED - Details-----")

    for instance_id, instance in ec2info.items():
        if instance['Type'] in not_scanned and instance['Private IP'] != None:
            for key in attributes:
                print("{0}: {1}".format(key, instance[key]))
            print("------")
    print "\n"

if __name__ == "__main__":


    ec2info = connect()
    public_ips(ec2info)
    private_ips(ec2info)
    public_ips_details(ec2info)
    private_ips_details(ec2info)





# get eips and instance ids

# client = boto3.client('ec2')
# addresses_dict = client.describe_addresses()
# for eip_dict in addresses_dict['Addresses']:
#     print eip_dict['PublicIp']
#     print eip_dict['InstanceId']
