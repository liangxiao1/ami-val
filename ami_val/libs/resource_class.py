from . import utils_lib

import boto3
import time
from botocore.exceptions import ClientError
from botocore.config import Config
import botocore.exceptions as boto_err
from tipset.libs import minilog, rmt_ssh
import json
import ami_val

from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

import os
from . import utils_lib
from filelock import FileLock

class FailException(Exception):
    pass
class SkipException(Exception):
    pass

class Result():
    def __init__(self):
        self.case_pass = 0
        self.case_fail = 0
        self.case_skip = 0
        self.case_error = 0
        self.run_time = 0
        self.cases = []

    @property
    def case_total(self):
        return self.case_pass + self.case_fail + self.case_skip + self.case_error

    @property
    def pass_rate(self):
        if self.case_total - self.case_skip > 0:
            pass_rate = self.case_pass/(self.case_total - self.case_skip) * 100
        else:
            pass_rate = 0
        return format(pass_rate,'0.2f')

class BaseTest():
    def __init__(self):
        self.info = None
        self.params = None
        self.vm = None
        self.logdir = None
        self.debuglog = None
        self.casename = None
        self.sumlog = None
        self.ssh_username = None
        self.ssh_keyfile = None
        self.keypairname = None
        self.instance_type = None
        self.subnet = None
        self.security_group = None
        self.tag_name = None
        self.ssh_conn = None
        self.instance_ip = None
        self.log = minilog.minilog()
        self.result = 'PASS'
        self.error = ''
        self.profile_name = 'aws'
        self.ssh_client = None
        self.resource_file = None
        self.resource_info = None

    def load_resource(self):
        self.resource_file = self.logdir + '/resource.json'
        with FileLock(self.resource_file + '.lock'):
            with open(self.resource_file,'r') as fh:
                tmp_resource = json.load(fh)
                for r in tmp_resource:
                    if r['ami'] == self.info['ami']:
                        self.resource_info = r
                        break

    def sum_log(self, result='', error=''):
        utils_lib.write_sumlog(self.sumlog,ami_id=self.info['ami'], ami_name=self.info['name'], region=self.info['region'], casename=self.casename, result=result, error=error)

    def fail(self, msg, is_raise=True):
        self.log.error(msg)
        self.error = msg
        self.result = 'FAIL'
        if is_raise:
            raise FailException(self.error)

    def skipTest(self, msg, is_raise=True):
        self.log.info(msg)
        self.error = msg
        self.result = 'SKIP'
        if is_raise:
            raise SkipException(self.error)

class EC2VM():
    __ec2_instance = None

    def __init__(self, testinstance):
        self.log = testinstance.log
        config = Config(retries=dict(max_attempts=2, ))
        self.profile_name = testinstance.profile_name
        if self.profile_name is None:
            self.profile_name = 'default'
        self.log.info('Load profile_name: {}'.format(self.profile_name))
        self.session = boto3.session.Session(profile_name=self.profile_name, region_name=testinstance.info.get('region'))
        self.__resource = self.session.resource('ec2', config=config)
        self.__client = self.session.client('ec2', config=config, region_name=testinstance.info.get('region'))
        #super(EC2VM, self).__init__(testinstance)
        self.instance_id = None
        self.ipv4 = None
        self.ami_id = testinstance.info['ami']
        self.resource_file = testinstance.logdir + '/resource.json'
        with FileLock(self.resource_file + '.lock'):
            with open(self.resource_file,'r') as fh:
                tmp_resource = json.load(fh)
                for r in tmp_resource:
                    if r['ami'] == self.ami_id:
                        self.resource = r
                        break  
        self.instance_type = None
        self.log.info("AMI picked {}, instance type {}".format(self.ami_id, self.instance_type))
        self.subnet = self.resource['subnet']
        self.sg = self.resource['sg']
        self.log.info("subnet {}, sg {}".format(self.subnet, self.sg))

        self.region = testinstance.info.get('region')
        # Config file
        cfg_file = os.path.dirname(ami_val.__file__) + "/cfg/ami-val.yaml"
        # Result dir
        with open(cfg_file,'r') as fh:
            keys_data = load(fh, Loader=Loader)
        self.tagname = keys_data['tag_name']

        self.ssh_key_name = keys_data['pair_name']
        self.ssh_key_path = keys_data['ssh_keyfile']
        self.ssh_username = keys_data['ssh_user']
        self.ssh_conn = None
        self.__volume_id = None
        self.is_created = False
        self.another_ip = None
        self.additionalinfo = None

    def reuse_init(self, instance_id):
        '''
        To reuse an exist instance than create a new one
        @params: instance_id id of existing instance
        '''
        self.log.info("reuse instance: {}".format(instance_id))
        if instance_id is None:
            return False
        try:
            self.__ec2_instance = self.__resource.Instance(instance_id)
            self.__ec2_instance.reload()
            self.log.info("instance state: {}".format(self.__ec2_instance.state))
            for x in range(10):
                if self.is_stopping():
                    self.log.info("Wait for 60 seconds, max 10 mins")
                    time.sleep(60)
                else:
                    break
            if self.is_stopping():
                self.log.info("Instance is still stopping, cannot use it ")
                return False
            if self.is_shutting_down():
                self.log.info("Instance is shutting-down, cannot reuse it")
                return False
            if self.is_deleted():
                self.log.info("Instance is terminated, cannot reuse it")
                return False
            self.log.info("Reuse {} without instance type check!".format(instance_id))
            self.is_created = False
            return True
        except Exception as err:
            self.log.info("reuse init failed: {}".format(err))
            return False

    def create(self, wait=True):
        self.is_created = False
        if self.additionalinfo == None or self.additionalinfo == '':
            if self.instance_type is None and len(self.resource['instance_types_list']) == 0:
                self.log.info("No instance type specified and instance_types_list is empty")
                return self.is_created
            for instance_type in self.resource['instance_types_list']:
                if self.instance_type is not None:
                    instance_type = self.instance_type
                self.log.info("try to create {}".format(instance_type))
                try:
                    self.__ec2_instance = self.__resource.create_instances(
                        ImageId=self.ami_id,
                        InstanceType=instance_type,
                        KeyName=self.ssh_key_name,
                        #SecurityGroupIds=[
                        #    self.security_group_ids,
                        #],
                        #SubnetId=self.subnet_id,
                        MaxCount=1,
                        MinCount=1,
                        #Placement={
                        #    'AvailabilityZone': self.zone,
                        #},
                        NetworkInterfaces=[
                            {
                                'AssociatePublicIpAddress': True,
                                'DeviceIndex': 0,
                                'SubnetId': self.subnet,
                                'Groups': [
                                     self.sg,
                                 ],
                            },
                        ],
                        TagSpecifications=[
                            {
                                'ResourceType': 'instance',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ]
                        )
                        #UserData='#!/bin/bash\nmkdir /home/%s/instance_create_%s' %
                        #(self.ssh_user, self.instance_type))[0]
                    self.is_created = True 
                    break
                except ClientError as err:
                    self.log.info("Failed to create instance!")
                    self.is_createable = False
                    self.log.info(err)
                except Exception as err:
                    self.log.info(err)

        if self.additionalinfo != None and self.additionalinfo != '':
            for additionalinfo in self.additionalinfo.split(';'):
                try:
                    self.log.info("Create instance using addtionalinfo: {}".format(additionalinfo))
                    self.__ec2_instance = self.__resource.create_instances(
                        ImageId=self.ami_id,
                        InstanceType=self.instance_type,
                        KeyName=self.ssh_key_name,
                        #SecurityGroupIds=[
                        #    self.security_group_ids,
                        #],
                        #SubnetId=self.subnet_id,
                        MaxCount=1,
                        MinCount=1,
                        AdditionalInfo=additionalinfo,
                        NetworkInterfaces=[
                        {
                            'AssociatePublicIpAddress': True,
                            'DeviceIndex': 0,
                            'SubnetId': self.subnet,
                            'Groups': [
                                 self.sg,
                             ],
                        },
                    ],
                        UserData='#!/bin/bash\nmkdir /home/%s/instance_create_%s' %
                        (self.ssh_user, self.instance_type))[0]
                    self.is_created = True
                except ClientError as err:
                    self.log.info("Failed to create instance, try another addtionalinfo {}".format(err))
                except Exception as err:
                    self.log.info("Failed to create instance, try another addtionalinfo {}".format(err))
                if self.is_created:
                    break
            if not self.is_created:
                raise err

        #self.create_tags()
        self.log.info(self.__ec2_instance)
        if self.is_created:
            self.__ec2_instance = self.__ec2_instance[0]
        else:
            return self.is_created
        if wait:
            try:
                self.__ec2_instance.wait_until_running()
                self.__ec2_instance.reload()
            except Exception as err:
                self.log.info("Failed to wait instance running!{}".format(err))

        self.instance_id = self.__ec2_instance.id
        # self.ipv4 = self.__ec2_instance.public_ip_address
        self.floating_ip
        self.boot_volume_id
        utils_lib.save_resource(self.resource_file, ami_id=self.ami_id, instance_id=self.__ec2_instance.id, log=self.log)
        return True

    def create_tags(self):
        try:
            self.__client.create_tags(Resources=[self.__ec2_instance.id],
                                      Tags=[{
                                          'Key': 'Name',
                                          'Value': self.tagname
                                      }])
            self.log.info("Added tag: {} to instance: {}".format(self.tagname, self.__ec2_instance.id))
        except ClientError as err:
            self.log.info("Failed to add tag to {}".format(self.__ec2_instance.id))

    def show(self):
        pass

    @property
    def res_id(self):
        '''
        return resource id for local resource management
        '''
        return self.__ec2_instance.id

    @property
    def res_type(self):
        '''
        return resource id for local resource management
        '''
        return self.__ec2_instance.instance_type

    @property
    def res_name(self):
        '''
        return resource name for local resource management
        '''
        return 'instance'

    def start(self, wait=True):
        try:
            self.__ec2_instance.start()
        except Exception as err:
            self.log.info(err)
            return False

        if wait:
            self.__ec2_instance.wait_until_running()
            if self.__ec2_instance.state['Name'] == 'running':
                self.log.info("Instance is in running state!")
            else:
                self.log.info(
                    "Instance is not in running state! It is in {} state!".format(self.__ec2_instance.state['Name']))
                return False
            self.__ec2_instance.reload()
            self.floating_ip
        return True

    def stop(self, wait=True, loops=4):
        try:
            self.log.info("Stopping instance {} ".format(self.instance_id))
            self.__ec2_instance.stop()
        except Exception as err:
            self.log.info("{}".format(err))
            return False

        if wait:
            for i in range(0, loops):
                self.log.info("Wait loop {}, max loop {}".format(i, loops))
                try:
                    self.__ec2_instance.wait_until_stopped()
                    return self.is_stopped()
                except boto_err.WaiterError as err:
                    self.log.info("{}".format(err))
            return self.is_stopped()
        return True

    def reboot(self, wait=True):
        '''
        Reboot from outside
        '''
        self.log.info("Rebooting instance: {}".format(self.instance_id))
        try:
            self.__ec2_instance.reload()
            self.__ec2_instance.reboot()
            if wait:
                if 'metal' in self.res_type:
                    time.sleep(120)
                else:
                    time.sleep(40)
            return True
        except Exception as err:
            self.log.info(err)
            return False

    def delete(self, wait=True, loops=4):
        try:
            self.log.info("Deleting instance: {}".format(self.__ec2_instance.id))
            self.__ec2_instance.terminate()
        except Exception as err:
            self.log.info(err)
            return False
        if wait:
            for i in range(0, loops):
                self.log.info("Wait loop {}, max loop {}".format(i, loops))
                try:
                    self.__ec2_instance.wait_until_terminated()
                    return self.is_deleted()
                except boto_err.WaiterError as err:
                    self.log.info(err)
            return self.is_deleted()
        return True

    def send_nmi(self):
        try:
            self.log.info("Send diagnostic interrupt to {}".format(self.__ec2_instance.id))
            self.__client.send_diagnostic_interrupt(
                InstanceId=self.__ec2_instance.id, DryRun=False)
            return True
        except ClientError as err:
            self.log.info("Failed to send_diagnostic_interrupt to {}".format(self.__ec2_instance.id))
            return False

    def exists(self):
        if self.__ec2_instance is None:
            self.log.info("Instance does not exist!")
            return False
        if self.is_deleted():
            self.log.info("Instance is in terminate state!")
            return False
        else:
            self.log.info("Instance exists: {}".format(self.instance_id))
            return True

    def is_started(self):
        try:
            self.__ec2_instance.reload()
            if self.__ec2_instance.state['Name'] == 'running':
                self.log.info("Instance is in running state!")
                return True
            else:
                self.log.info(
                    "Instance is not in running state! It is in {} state".format(self.__ec2_instance.state['Name']))
                return False
        except Exception as err:
            self.log.info(err)
            return False

    def is_stopped(self):
        self.__ec2_instance.reload()
        if self.__ec2_instance.state['Name'] == 'stopped':
            self.log.info("Instance is in stopped state!")
            return True
        else:
            self.log.info("Instance is not in stopped state! It is in {} state!".format(self.__ec2_instance.state['Name']))
            return False

    def is_stopping(self):
        self.__ec2_instance.reload()
        if self.__ec2_instance.state['Name'] == 'stopping':
            self.log.info("Instance is in stopping state!")
            return True
        else:
            self.log.info("Instance is not in stopping state! It is in {} state!".format(self.__ec2_instance.state['Name']))
            return False

    def is_shutting_down(self):
        self.__ec2_instance.reload()
        if self.__ec2_instance.state['Name'] == 'shutting-down':
            self.log.info("Instance is in shutting-down state!")
            return True
        else:
            self.log.info(
                "Instance is not in shutting-down state! It is in {} state!".format(self.__ec2_instance.state['Name']))
            return False

    def is_deleted(self):
        try:
            self.__ec2_instance.reload()
            if self.__ec2_instance.state['Name'] == 'terminated':
                self.log.info("Instance is in terminated state!")
                return True
            else:
                self.log.info(
                    "Instance is not in terminated state! It is in {} state!".format(self.__ec2_instance.state['Name']))
                return False
        except Exception as err:
            self.log.info("Failed to get instance status, it may not exist! {}".format(err))     
            return True

    @property
    #@utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def floating_ip(self, interval=2, timeout=90):
        start_time = time.time()
        while True:
            self.log.info("reload and get public ip")
            self.__ec2_instance.reload()
            self.ipv4 = self.__ec2_instance.public_dns_name
            if self.ipv4 is not None:
                break
            end_time = time.time()
            time.sleep(interval)
            if end_time - start_time > timeout:
                log.info('timeout, break!')
                break
        self.log.info("Public ip is: {}".format(self.ipv4))
        return self.ipv4

    @property
    def priviate_ip(self):
        self.__ec2_instance.reload()
        self.log.info("Private ip is: {}".format(self.__ec2_instance.private_ip_address))
        return self.__ec2_instance.private_ip_address

    @property
    def boot_volume_id(self):
        for i in self.__ec2_instance.volumes.all():
            if 'sda' in i.attachments[0].get('Device') \
                    or 'xvda' in i.attachments[0].get('Device') \
                    or 'nvme0' in i.attachments[0].get('Device'):
                self.__volume_id = i.id
                self.log.info("Boot volume id: {}".format(self.__volume_id))
                return self.__volume_id
        return None

    @property
    def primary_nic_id(self):
        for nic in self.__ec2_instance.network_interfaces_attribute:
            if nic['Attachment']['DeviceIndex'] == 0:
                return nic['NetworkInterfaceId']
        self.log.info("primary nic id not found")
        return None

    def assign_new_ip(self):
        nic = self.__resource.NetworkInterface(self.primary_nic_id)
        ret = nic.assign_private_ip_addresses(
                AllowReassignment=True,
                SecondaryPrivateIpAddressCount=1
            )
        self.another_ip = ret['AssignedPrivateIpAddresses'][0]['PrivateIpAddress']
        self.log.info("second nic ip{}".format(self.another_ip))
        return self.another_ip
    
    def remove_added_ip(self):
        nic = self.__resource.NetworkInterface(self.primary_nic_id)
        if self.another_ip is None:
            self.log.info("second nic ip is {}".format(self.another_ip))
            return False
        try:
            ret = nic.unassign_private_ip_addresses(
                    PrivateIpAddresses=[
                        self.another_ip,
                    ]
                )
            self.log.info("removed second nic ip{}".format(self.another_ip))
            return True
        except Exception as err:
            self.log.info(err)
        return False

    def get_volumes_id(self):
        volumes_list = []
        self.log.info("Try to get all attached volumes!")
        self.__ec2_instance.reload()
        for i in self.__ec2_instance.volumes.all():
            volumes_list.append(i.id)
        self.log.info(volumes_list)
        return volumes_list

    def get_cpu_count(self):
        volumes_list = []
        self.log.info("Try to get instance cpu count")
        self.__ec2_instance.reload()
        cpuinfo = self.__ec2_instance.cpu_options
        cpucount = int(cpuinfo['CoreCount']) * int(cpuinfo['ThreadsPerCore'])
        self.log.info("got {}".format(cpucount))
        return cpucount

    def get_console_log(self):
        try:
            output = self.__ec2_instance.console_output(Latest=True).get('Output')
            return True, output
        except Exception as err:
            self.log.info("Failed to get console log, try without latest! {}".format(err))
        try:
            output = self.__ec2_instance.console_output().get('Output')
            return True, output
        except Exception as err:
            self.log.info("Failed to get console log! {}".format(err))
            return False, err

    def modify_instance_type(self, new_type):
        try:
            self.__ec2_instance.modify_attribute(
                InstanceType={'Value': new_type})
            self.instance_type = new_type
            return True
        except Exception as err:
            self.log.info("Failed to change instance type to {}, ret:{}".format(new_type, err)) 
            return False

    def new_ssh_client(self):
        return rmt_ssh.build_connection(rmt_node=self.floating_ip, rmt_user=self.ssh_username, rmt_password=None, rmt_keyfile=self.ssh_key_path, timeout=180, log=self.log)

    def is_image_ena_enabled(self):
        try:
            image = self.__resource.Image(self.ami_id)
            return image.ena_support
        except Exception as err:
            self.log.info('Cannot get image ena_support status.{}'.format(err))
            return False
