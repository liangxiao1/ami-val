import sys
import os
import logging
import ami_val
import json
import copy
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Please install boto3")
    sys.exit(1)

from tipset.libs import minilog
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

import concurrent.futures
from . import utils_lib

def aws_init_key(region=None, profile=None, log=None):
    if log is None:
        log = minilog.minilog()
    default_regions = ['us-west-2', 'cn-northwest-1', 'us-gov-west-1']
    if region is None:
        default_regions = ['us-west-2', 'cn-northwest-1', 'us-gov-west-1']
    else:
        default_regions = [region]
    if profile is None:
        profile = 'default'
    log.info("Use profile:{} in region {}".format(profile,default_regions))
    ec2_resource = None
    ec2_client = None
    for region in default_regions:
        try:
            session = boto3.session.Session(profile_name=profile, region_name=region)
            ec2_resource = session.resource('ec2', region_name=region)
            ec2_client = session.client('ec2', region_name=region)
            region_list = ec2_client.describe_regions()['Regions']
            log.info("Init key in region {} successfully".format(region))
            break
        except Exception as error:
            log.info("Try to init in region:{} result:{}".format(region,str(error)))
    if ec2_resource is None:
        log.error('Unable to init {} in any region'.format(profile))
        sys.exit(1)
    return ec2_resource, ec2_client

def aws_vpc_sg_find(vpcid, region, profile_name, log=None):
    '''
    if the vpc's default security group allow ssh connection
    return None or sg id
    '''
    if log is None:
        log = minilog.minilog()
    ec2, _ = aws_init_key(region,profile=profile_name, log=log)
    try:
        vpc = ec2.Vpc(vpcid)
        log.info("vpc init {}".format(vpcid))
    except Exception as error:
        log.info("vpc init error {}, {}", vpcid, str(error))
        return None
    try:
        sgs = vpc.security_groups.all()
    except Exception as error:
        log.info("default sg get error: {}".format(str(error)))
        return None
    for sg in sgs:
        try:
            sg = ec2.SecurityGroup(sg.id)
            ips = sg.ip_permissions
            for ip in ips:
                ip_ranges = ip['IpRanges']
                log.debug(ip_ranges)
                for ip_range in ip_ranges:
                    if '0.0.0.0/0' in ip_range['CidrIp']:
                        log.info("found security group:{} vpc check pass!".format(sg.id))
                        security_group_id = sg.id
                        return security_group_id
            log.info("ssh enabled security group not found in {}".format(vpcid))
        except Exception as error:
            log.info("sg init error {}, error:{}".format(sg.id, error))
    return None

def aws_vpc_create(region, profile_name, tag, log=None):
    '''
    create a new vpc for test running
    '''
    if log is None:
        log = minilog.minilog()
    log.info("create a new vpc for test running")
    ec2, client = aws_init_key(region,profile=profile_name, log=log)
    default_tag = 'virtqe'
    if tag is None:
        tag = default_tag
    try:
        vpc_new = client.create_vpc(
            CidrBlock='192.111.0.0/16',
            AmazonProvidedIpv6CidrBlock=True,
            DryRun=False,
            InstanceTenancy='default'
        )
    except Exception as err:
        log.info("Failed to create vpc {}".format(str(err)))
    vpcid = vpc_new['Vpc']['VpcId']
    log.info("New vpc created {}".format(vpcid))
    try:
        vpc = ec2.Vpc(vpcid)
        log.info("vpc init {}".format(vpcid))
        tag = vpc.create_tags(
            DryRun=False,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': tag
                },
            ]
        )
        log.info("added tag to vpc: {}".format(tag))
        vpc.modify_attribute(
            EnableDnsHostnames={
                'Value': True
            }
        )
        log.info("Enabled dns support")
    except Exception as error:
        log.info(str(error))
        return False
    igw = aws_igw_create(client, vpcid, tag)
    if igw == None:
        return vpc
    rt = aws_rt_update(client, vpc, igw, tag)
    if rt == None:
        return vpc
    subnet = aws_subnet_create(client, vpc, tag)
    if subnet == None:
        return vpc
    sg = aws_sg_update(client, vpc, igw, tag)
    if sg == None:
        return vpc

def aws_subnet_find(region, profile, create_new=True, log=None):
    '''
    if subnet enable public ipv4 on launch.
    return None or subnet id
    '''
    if log is None:
        log = minilog.minilog()
    _, client = aws_init_key(region,profile=profile, log=log)
    subnet_id = None
    sg_id = None
    subnets = client.describe_subnets()['Subnets']
    for subnet in subnets:
        if subnet['MapPublicIpOnLaunch']:
            vpc_id = subnet['VpcId']
            sg_id = aws_vpc_sg_find(vpc_id, region, profile, log=log)
            if sg_id:
                subnet_id = subnet['SubnetId']
                break
    if subnet_id is None and create_new:
        log.info("No ipv4 pub enabed subnets found in region {}".format(region))
        vpc = aws_vpc_create(region, profile, 'virtqe')
        subnets = client.describe_subnets()['Subnets']
        for subnet in subnets:
            if subnet['MapPublicIpOnLaunch']:
                vpc_id = subnet['VpcId']
                sg_id = aws_vpc_sg_find(vpc_id, region, profile, log=log)
                if sg_id:
                    subnet_id = subnet['SubnetId']
                    break
    if subnet_id is None:
        log.info("No proper subnet(ssh enabled) found in {}, please check manually!".format(region))
    log.info("Found existing subnet: {} in region {}".format(subnet_id, region))
    return subnet_id, sg_id, region

def aws_igw_create(region, profile, vpcid, tag, log=None):
    '''
    create a new igw and attach to vpc
    '''
    if log is None:
        log = minilog.minilog()
    ec2, client = aws_init_key(region,profile=profile, log=log)
    default_tag = 'virtqe'
    if tag is None:
        tag = default_tag
    try:
        igw_new = client.create_internet_gateway(
            DryRun=False
        )
        igwid = igw_new['InternetGateway']['InternetGatewayId']
        log.info("New igw created {}".format(igwid))
        igw = ec2.InternetGateway(igwid)
        igw.create_tags(
            DryRun=False,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': tag
                },
            ]
        )
        igw.attach_to_vpc(
            DryRun=False,
            VpcId=vpcid
        )
        return igw
    except Exception as err:
        if 'Resource.AlreadyAssociated' in str(err):
            return igw
        log.info(str(err))
        return None

def aws_rt_update(region, profile, vpcid, igwid, tag, log=None):
    '''
    update default route table
    '''
    if log is None:
        log = minilog.minilog()
    ec2, client = aws_init_key(region,profile=profile, log=log)
    default_tag = 'virtqe'
    if tag is None:
        tag = default_tag
    try:
        vpc = ec2.Vpc(vpcid)
        igw = ec2.InternetGateway(igwid)
        rts = vpc.route_tables.all()
        for i in rts:
            for x in i.associations_attribute:
                if x['Main']:
                    log.info("found route table, {}".format(i.id))
                    rt = i
        #rt = vpc.create_route_table(
        #    DryRun=False,
        #
        #)
        #log.info("New route table created %s", rt.id)
        log.info("Update route table {}".format(rt.id))
        rt.create_tags(
            DryRun=False,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': tag
                },
            ]
        )
        log.info("tag added")
        route = rt.create_route(
            DestinationCidrBlock='0.0.0.0/0',
            DryRun=False,
            GatewayId=igw.id,
        )
        return rt
    except Exception as err:
        log.info(str(err))
        return None

def aws_sg_update(region, profile, vpcid, tag, log=None):
    '''
    update default security group
    '''
    if log is None:
        log = minilog.minilog()
    ec2, client = aws_init_key(region,profile=profile, log=log)
    default_tag = 'virtqe'
    if tag is None:
        tag = default_tag
    try:
        vpc = ec2.Vpc(vpcid)
        sgs = vpc.security_groups.all()
        sg = None
        for i in sgs:
            log.debug("sg name {}".format(i.group_name))
            if "default" in i.group_name:
                sg = i
                break
        if sg == None:
            log.info("No default named security group")
            return None
    except Exception as error:
        log.info("default sg get error: {}".format(str(error)))
        return None
    try:
        #sg = vpc.create_security_group(
        #    Description='virtqe s1',
        #    GroupName='default',
        #    DryRun=True
        #)
        #log.info("New security group created %s", sg.id)
        sg.create_tags(
            DryRun=False,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': tag
                },
            ]
        )
        log.info("tag added")
        response = sg.authorize_ingress(
            IpPermissions=[
                {
                    "PrefixListIds": [],
                    "FromPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "UserIdGroupPairs": [],
                    "Ipv6Ranges": []
                },
                {
                    "PrefixListIds": [],
                    "FromPort": -1,
                    "IpRanges": [],
                    "ToPort": -1,
                    "IpProtocol": "icmpv6",
                    "UserIdGroupPairs": [],
                    "Ipv6Ranges": [
                        {
                            "CidrIpv6": "::/0"
                        }
                    ]
                },
                {
                    "PrefixListIds": [],
                    "FromPort": -1,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "ToPort": -1,
                    "IpProtocol": "icmp",
                    "UserIdGroupPairs": [],
                    "Ipv6Ranges": []
                }
            ]
        )
        log.info("Enabled ssh port created {}".format(sg.id))
        return sg
    except Exception as err:
        log.info(str(err))
        return None

def aws_subnet_create(region, profile, vpcid, tag, log=None):
    '''
    create a new subnet
    '''
    if log is None:
        log = minilog.minilog()
    ec2, client = aws_init_key(region,profile=profile, log=log)
    default_tag = 'virtqe'
    if tag is None:
        tag = default_tag
    try:
        vpc = ec2.Vpc(vpcid)
        subnet = vpc.create_subnet(
            CidrBlock='192.111.1.0/24',
            DryRun=False
        )
        log.info("New subnet created {}".format(subnet.id))
        subnet.create_tags(
            DryRun=False,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': tag
                },
            ]
        )
        log.info("tag added")
        client.modify_subnet_attribute(
            MapPublicIpOnLaunch={
                'Value': True
            },
            SubnetId=subnet.id
        )
        log.info("enabled ipv4 on launch")
        return subnet
    except Exception as err:
        log.info(str(err))
        return None

def aws_import_key(region=None, profile=None, keyname=None, pubkeyfile=None, log=None):
    '''
    if keyname does not exists, try to import it.
    '''
    if log is None:
        log = minilog.minilog()
    ec2_resource, ec2_client = aws_init_key(region, profile, log=log)
    try:
        keypair = ec2_resource.KeyPair(keyname)
        keypair.key_pair_id
        log.info("{} exists.".format(keyname))
        return True
    except Exception as exc:
        log.info("{} not found with error {}".format(keyname,exc))

    pubkeystr = None
    if not os.path.exists(pubkeyfile):
        log.info("{} not found, do not try to import local key".format(pubkeyfile))
        return False
    with open(pubkeyfile, 'r') as fh:
        pubkeystr=fh.readlines()[0]
    try:
        response = ec2_client.import_key_pair(
            DryRun=False,
            KeyName=keyname,
            PublicKeyMaterial=pubkeystr
        )
        log.info("{} added!".format(keyname))
    except Exception as error:
        if 'Duplicate' in str(error):
            log.info("{} already exists in {}".format(keyname, region))
        else:
            log.info(error)

def aws_find_region_missed(profile=None,resource_file=None, log=None):
    if log is None:
        log = minilog.minilog()
    ec2_resource, ec2_client = aws_init_key(profile=profile, log=log)
    region_list = ec2_client.describe_regions()['Regions']
    region_name_list = [region['RegionName'] for region in region_list]
    missed_list = copy.deepcopy(region_name_list)
    has_list = []
    with open(resource_file,'r') as fh:
        tmp_resource = json.load(fh)
        for r in tmp_resource:
            if r['region'] in region_name_list and r['region'] in missed_list:
                missed_list.remove(r['region'])
            if r['region'] not in has_list:
                has_list.append(r['region'])
    return missed_list, has_list

    
def aws_check_all_regions(profile=None, is_paralle=True, log=None, resource_file=None):
    '''
    this func checks all regions has keypair required.
    and search subnet, sg to allow to create instance and make ssh connection
    '''
    # Config file
    cfg_file = os.path.dirname(ami_val.__file__) + "/cfg/ami-val.yaml"
    # Result dir
    with open(cfg_file,'r') as fh:
       keys_data = load(fh, Loader=Loader)
    if log is None:
        log = minilog.minilog()
    keyname, pubkeyfile = keys_data['pair_name'], keys_data['ssh_pubfile']
    ec2_resource, ec2_client = aws_init_key(profile=profile, log=log)
    region_list = ec2_client.describe_regions()['Regions']
    log.info("Checking keypair exists in all regions......")
    if is_paralle:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            all_jobs = {executor.submit(aws_import_key, region['RegionName'], profile, keyname, pubkeyfile): region for region in region_list}
            for r in concurrent.futures.as_completed(all_jobs, timeout=1200):
                x = all_jobs[r]
                try:
                    data = r.result()
                except Exception as exc:
                    print("{} generated an exception: {}".format(r,exc))
                else:
                    pass
    else:
        for region in region_list:
            aws_import_key(region=region['RegionName'], profile=profile, keyname=keyname, pubkeyfile=pubkeyfile)
    log.info("Searching proper subnet and security group in all regions......")
    if is_paralle:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            all_jobs = {executor.submit(aws_subnet_find, region['RegionName'], profile=profile, create_new=False): region for region in region_list}
            for r in concurrent.futures.as_completed(all_jobs, timeout=1200):
                x = all_jobs[r]
                try:
                    data = r.result()
                    log.info(r.result())
                    utils_lib.save_resource(resource_file, region=data[2], subnet=data[0], sg=data[1])
                except Exception as exc:
                    print("{} generated an exception: {}".format(r,exc))
                else:
                    pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            all_jobs = {executor.submit(aws_instance_type_find, region['RegionName'], profile=profile, arch='arm64'): region for region in region_list}
            for r in concurrent.futures.as_completed(all_jobs, timeout=1200):
                x = all_jobs[r]
                try:
                    data = r.result()
                    log.info(r.result())
                    utils_lib.save_resource(resource_file, region=data[0], arch='arm64', instance_types_list=data[1])
                except Exception as exc:
                    print("{} generated an exception: {}".format(r,exc))
                else:
                    pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            all_jobs = {executor.submit(aws_instance_type_find, region['RegionName'], profile=profile, arch='x86_64'): region for region in region_list}
            for r in concurrent.futures.as_completed(all_jobs, timeout=1200):
                x = all_jobs[r]
                try:
                    data = r.result()
                    log.info(r.result())
                    utils_lib.save_resource(resource_file, region=data[0], arch='x86_64', instance_types_list=data[1])
                except Exception as exc:
                    print("{} generated an exception: {}".format(r,exc))
                else:
                    pass
    
    else:
        for region in region_list:
            subnet_id, sg_id, region_name = aws_subnet_find(region=region['RegionName'], profile=profile, create_new=False)
            #log.info('{} {} {}'.format(subnet_id, sg_id, region_name))
            utils_lib.save_resource(resource_file, region=region_name, subnet=subnet_id, sg=sg_id)
            _, instance_type_arm = aws_instance_type_find(region=region['RegionName'], profile=profile, arch='arm64')
            _, instance_type_x86 = aws_instance_type_find(region=region['RegionName'], profile=profile, arch='x86_64')
            utils_lib.save_resource(resource_file, region=region['RegionName'], arch='arm64', instance_types_list=instance_type_arm)
            utils_lib.save_resource(resource_file, region=region['RegionName'], arch='x86_64', instance_types_list=instance_type_x86)


def aws_check_region(region=None, profile=None, log=None, resource_file=None):
    '''
    this func checks all regions has keypair required.
    and search subnet, sg to allow to create instance and make ssh connection
    '''
    # Config file
    cfg_file = os.path.dirname(ami_val.__file__) + "/cfg/ami-val.yaml"
    # Result dir
    with open(cfg_file,'r') as fh:
       keys_data = load(fh, Loader=Loader)
    if log is None:
        log = minilog.minilog()
    keyname, pubkeyfile = keys_data['pair_name'], keys_data['ssh_pubfile']
    ec2_resource, ec2_client = aws_init_key(profile=profile, log=log)
    log.info("Checking keypair exists in {}......".format(region))
    aws_import_key(region=region, profile=profile, keyname=keyname, pubkeyfile=pubkeyfile, log=log)
    log.info("Searching proper subnet and security group in {}......".format(region))
    subnet_id, sg_id, region_name = aws_subnet_find(region=region, profile=profile, create_new=False, log=log)
    #log.info('{} {} {}'.format(subnet_id, sg_id, region_name))
    utils_lib.save_resource(resource_file, region=region, subnet=subnet_id, sg=sg_id, log=log)
    _, instance_type_arm = aws_instance_type_find(region=region, profile=profile, arch='arm64', log=log)
    _, instance_type_x86 = aws_instance_type_find(region=region, profile=profile, arch='x86_64', log=log)
    utils_lib.save_resource(resource_file, region=region, arch='arm64', instance_types_list=instance_type_arm, log=log)
    utils_lib.save_resource(resource_file, region=region, arch='x86_64', instance_types_list=instance_type_x86, log=log)

def aws_instance_type_find(region=None, profile=None, arch=None, skip_metal=True, max_mem=32, log=None):
    '''
    arch: arm64 | i386 | x86_64
    '''
    if log is None:
        log=minilog.minilog()
    _, ec2_client = aws_init_key(region=region, profile=profile, log=log)
    instance_types_list = []
    filters = []
    if arch is not None:
        filters.append({
                'Name': 'processor-info.supported-architecture',
                'Values': [
                    arch,
                ]
            })
    if skip_metal:
        filters.append({
                'Name': 'bare-metal',
                'Values': [
                    'false',
                ]
            })
    filters.append({
                'Name': 'memory-info.size-in-mib',
                'Values': [
                    str(max_mem*1024),
                ]
            })
    
    tmp_dict_all = ec2_client.describe_instance_types(Filters=filters)
    i = 0
    while True:
        #log.info('Get loop {}'.format(i))
        i = i + 1
        tmp_dict = tmp_dict_all['InstanceTypes']
        instance_types_list.extend(tmp_dict)
        try:
            nexttoken = tmp_dict_all['NextToken']
        except KeyError as err:
            log.info("Get instance types done, length {}".format(len(instance_types_list)))
            break
        if nexttoken == None:
            log.info("Get instance types done, length {}".format(len(instance_types_list)))
            break
        tmp_dict_all = ec2_client.describe_instance_types(NextToken=nexttoken, Filters=filters)
    instance_list = [ x['InstanceType'] for x in instance_types_list ]
    return region, instance_list
    
