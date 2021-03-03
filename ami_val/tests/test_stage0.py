import json
from ami_val.libs import utils_lib, resource_class, aws_lib

def test_stage0_check_aminame(test_instance):
    aminame = test_instance.info['name']
    if 'RHEL' in aminame:
        test_instance.log.info("RHEL is expected and found in AMI's name in push task")
        if 'SAP' in aminame:
            if 'Access2' in aminame:
                test_instance.fail('the -access images are not needed for this sap image set.(RHELDST-4739)')
    else:
        test_instance.fail('RHEL is expected in AMI name but get {} in push task'.format(aminame))
    test_instance.log.info("Details:{}".format(json.dumps(test_instance.info, indent=4)))

def test_stage0_check_ena_enabled(test_instance):
    if test_instance.info['ena_support'] != 'true':
        test_instance.log.info('ena_support is enabled in push task')
    else:
        test_instance.fail('ena_support is expected true but get {} in push task'.format(test_instance.info['ena_support']))
    test_instance.log.info("Details:{}".format(json.dumps(test_instance.info, indent=4)))

def test_stage0_launch_instance(test_instance):
    '''
    launch instances from AMIs in all supported regions
    '''
    aws_lib.aws_check_region(region=test_instance.info['region'], profile=test_instance.profile_name, resource_file=test_instance.resource_file, log=test_instance.log)
    vm = resource_class.EC2VM(test_instance)
    if vm.create():
        test_instance.vm = vm
        test_instance.ssh_client = vm.new_ssh_client()
