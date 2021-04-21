import json
from ami_val.libs import utils_lib, resource_class, aws_lib
import re

def test_stage0_check_aminame(test_instance):
    test_instance.log.info("Details:{}".format(json.dumps(test_instance.info, indent=4)))
    aminame = test_instance.info['name']
    if 'RHEL' in aminame:
        test_instance.log.info("RHEL is expected and found in AMI's name in push task")
        if 'SAP' in aminame:
            if 'Access2' in aminame:
                test_instance.fail('the -access images are not needed for this sap image set.(RHELDST-4739)')
        if 'HA' in aminame:
            if 'arm64' in aminame:
                test_instance.fail('We don’t support aarch64 in RHEL HA(mail confirmed), so no need to include it in push task')
    elif utils_lib.is_fedora(test_instance):
        ami_format = 'Fedora-Cloud-Base-[\d]{2}-[\d]{8}.n.[\d].(?:aarch64|x86_64)'
        if re.match(ami_format, aminame):
            test_instance.log.info('{} check pass'.format(aminame))
        else:
            test_instance.fail('{} not match {}'.format(aminame, ami_format))
    else:
        test_instance.fail('RHEL is expected in AMI name but get {} in push task'.format(aminame))

def test_stage0_check_ena_set_in_push(test_instance):
    test_instance.log.info("Details:{}".format(json.dumps(test_instance.info, indent=4)))
    aminame = test_instance.info['name']
    if aminame.startswith(('RHEL-6','RHEL-7.0','RHEL-7.1','RHEL-7.2','RHEL-7.3')):
        if test_instance.info['ena_support']:
            test_instance.fail('ena_support should be disabled in push task before RHEL-7.4, acutal {}'.format(test_instance.info['ena_support']))
        else:
            test_instance.log.info('ena_support is disabled as expected in push task before RHEL-7.4, acutal: {}'.format(test_instance.info['ena_support']))
    else:
        if not test_instance.info['ena_support']:
            test_instance.fail('ena_support should be enabled in push task after RHEL-7.4, acutal: {}'.format(test_instance.info['ena_support']))
        else:
            test_instance.log.info('ena_support is enabled as expected in push task after RHEL-7.4, acutal: {}'.format(test_instance.info['ena_support']))

def test_stage0_launch_instance(test_instance):
    '''
    launch instances from AMIs in all supported regions
    '''
    aws_lib.aws_check_region(region=test_instance.info['region'], profile=test_instance.profile_name, resource_file=test_instance.resource_file, log=test_instance.log)
    vm = resource_class.EC2VM(test_instance)
    if vm.create():
        test_instance.vm = vm
        test_instance.ssh_client = vm.new_ssh_client()
        if test_instance.ssh_client is None:
            test_instance.fail("No ssh connection created")
