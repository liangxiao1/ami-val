import os
import re
import sys
import time
import json
from ami_val.libs.utils_lib import run_cmd, get_product_id, getboottime
import ami_val
from filelock import FileLock
import csv

def test_stage2_check_auditd(test_instance):
    """
    Check auditd:
    - service should be on
    - no change to the audit pkg
    """
    if 'ATOMIC' in test_instance.info['name'].upper():
        test_instance.skipTest('skip run in Atomic AMIs')
    if 'RHEL-6' in test_instance.info['name'].upper():
        cmd = 'sudo service auditd status'
    else:
        cmd = 'sudo systemctl is-active auditd'
    run_cmd(test_instance, cmd, expect_ret=0, msg='check if auditd service is active')
    out = run_cmd(test_instance, 'sudo cat /etc/redhat-release', expect_ret=0, msg='get release name')
    run_cmd(test_instance, 'sudo rpm -V audit', expect_ret=0)

def test_stage2_check_ha_specific(test_instance):
    if 'HA' not in test_instance.info['name'] and 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in HA AMIs or RHEL-8+ SAP AMIs')

    product_id = get_product_id(test_instance)
    if float(product_id) < float('8') and 'SAP' in test_instance.info['name']:
        test_instance.skipTest('skip in earlier than el8 SAP AMIs')
    script_dir = os.path.realpath(ami_val.__file__)
    script_dir = os.path.dirname(script_dir)
    script_file = script_dir + '/scripts/rhel-ha-aws-check.sh'
    rmt_file = '/tmp/rhel-ha-aws-check.sh'
    ftp_client = test_instance.ssh_client.open_sftp()
    ftp_client.put(script_file, rmt_file)
    run_cmd(test_instance, 'sudo chmod 555 {}'.format(rmt_file), msg='make it executeable')
    run_cmd(test_instance, 'sudo {} 2>&1'.format(rmt_file), expect_ret=0, msg='run ha test', timeout=1800)

def test_stage2_check_libc6_xen_conf(test_instance):
    """
    check for /etc/ld.so.conf.d/libc6-xen.conf absence on RHEL
    """
    run_cmd(test_instance, 'sudo test -f /etc/ld.so.conf.d/libc6-xen.conf', expect_ret=1, msg='check for /etc/ld.so.conf.d/libc6-xen.conf absence on RHEL')

def test_stage2_check_sap_security_limits(test_instance):
    '''
    rhbz:1959963
    RHELDST-10710
    '''
    if 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in SAP AMIs')
    options = ['@sapsys hard nofile 1048576','@sapsys soft nofile 1048576',
               '@dba hard nofile 1048576','@dba soft nofile 1048576',
               '@sapsys hard nproc unlimited','@sapsys soft nproc unlimited',
               '@dba hard nproc unlimited','@dba soft nproc unlimited']
    
    cmd = "sudo cat /etc/security/limits.d/99-sap.conf|awk -F' ' '{print($1,$2,$3,$4)}'"
    result = run_cmd(test_instance, cmd, msg='check /etc/security/limits.d/99-sap.conf')
    run_cmd(test_instance, cmd, expect_kw=','.join(options), msg='check /etc/security/limits.d/99-sap.conf')

def test_stage2_check_sap_sysctl(test_instance):
    '''
    rhbz: 1959962
    kernel.pid_max = 4194304
    vm.max_map_count = 2147483647
    file path: /usr/lib/sysctl.d/sap.conf or /etc/sysctl.d/sap.conf
    '''
    if 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in SAP AMIs')
    check_dict = {
        "kernel.pid_max":"4194304",
        "vm.max_map_count":"2147483647"
    }
    for k in check_dict.keys():
        run_cmd(test_instance, 'sudo sysctl {}'.format(k), expect_kw=check_dict.get(k))

def test_stage2_check_sap_tmpfiles(test_instance):
    '''
    rhbz: 1959979
    file path: /usr/lib/tmpfiles.d/sap.conf or /etc/tmpfiles.d/sap.conf
    '''
    if 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in SAP AMIs')
    expected_cfg =  'x /tmp/.sap*,x /tmp/.hdb*lock,x /tmp/.trex*lock'
    cmd = 'sudo cat /usr/lib/tmpfiles.d/sap.conf /etc/tmpfiles.d/sap.conf'
    run_cmd(test_instance, cmd, expect_kw=expected_cfg)

def test_stage2_check_sap_tuned(test_instance):
    '''
    rhbz: 1959962
    '''
    if 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in SAP AMIs')
    expected_cfg =  'sap-hana'
    cmd = 'sudo cat /etc/tuned/active_profile'
    run_cmd(test_instance, cmd, expect_kw=expected_cfg, msg='check /etc/tuned/active_profile')
    cmd = 'sudo tuned-adm active'
    run_cmd(test_instance, cmd, expect_kw=expected_cfg, msg='check tuned-adm active output')

def test_stage2_check_ttyS0_conf(test_instance):
    """
    bz: 1103344
    check no "/etc/init/ttyS0.conf" exists.
    check no "/dev/ttyS0: tcgetattr: Input/output error" in "/var/log/secure"
    """
    run_cmd(test_instance, 'sudo cat /etc/init/ttyS0.conf', expect_not_ret=0, msg='make sure no /etc/init/ttyS0.conf found')
    run_cmd(test_instance, 'sudo cat /etc/init/ttyS0.bak', msg='ttyS0.bak may also not in RHEL nowadays')

def test_stage2_test_reboot_grubby(test_instance):
    '''
    check user can update boot parameter using grubby tool
    '''

    run_cmd(test_instance, 'sudo grubby --update-kernel=ALL --args="kmemleak=on"', msg='append boot parameter')
    test_instance.ssh_client.close()
    test_instance.vm.reboot()
    test_instance.ssh_client = test_instance.vm.new_ssh_client()
    run_cmd(test_instance, 'sudo cat /proc/cmdline', expect_kw="kmemleak=on", msg='check if the parameter has been added')
    run_cmd(test_instance, 'sudo grubby --update-kernel=ALL --remove-args="kmemleak=on"', msg='remove the appended boot parameter')

def test_stage2_test_reboot_hostname(test_instance):
    '''
    check that reboot doesn't change the hostname
    '''

    hostname_1 = run_cmd(test_instance, 'hostname', expect_ret=0, msg='get hostname before reboot')
    test_instance.ssh_client.close()
    test_instance.vm.reboot()
    test_instance.ssh_client = test_instance.vm.new_ssh_client()
    run_cmd(test_instance, 'last', expect_ret=0, msg='get last history')
    run_cmd(test_instance, 'hostname', expect_ret=0, expect_kw=hostname_1, msg='check hostname after reboot')

def test_stage2_test_rebootime(test_instance):
    '''
    rhbz: 1776710, 1446698, 1446688
    check reboot time after 1st init.
    can change pass criteria in cfg ami-val.yaml, default is 30s.
    '''

    aminame = test_instance.info['name']
    if aminame.startswith('RHEL-6'):
        test_instance.skipTest('no systemd-analyze in el6')
    test_instance.ssh_client.close()
    test_instance.vm.reboot()
    test_instance.ssh_client = test_instance.vm.new_ssh_client()
    boottime = getboottime(test_instance)
    test_instance.tmp_data['BootTime']['RebootTime'] = boottime
    if float(boottime) > float(test_instance.params['max_reboot_time']):
        test_instance.fail('boot time {} over expected {}'.format(boottime, test_instance.params['max_reboot_time']))
    else:
        test_instance.log.info('boot time {} within expected {}'.format(boottime, test_instance.params['max_reboot_time']))

def test_stage2_test_stop_start_bootime(test_instance):
    '''
    check reboot time after stop
    can change pass criteria in cfg ami-val.yaml, default is 30s.
    '''

    aminame = test_instance.info['name']
    if aminame.startswith('RHEL-6'):
        test_instance.skipTest('no systemd-analyze in el6')
    test_instance.ssh_client.close()
    test_instance.vm.stop()
    test_instance.vm.start()
    test_instance.ssh_client = test_instance.vm.new_ssh_client()
    boottime = getboottime(test_instance)
    test_instance.tmp_data['BootTime']['Stop-StartTime'] = boottime
    test_instance.log.info(test_instance.tmp_data)
    boottime_csv = test_instance.logdir + '/bootimes.csv'
    test_instance.log.info("boot time data are saving to {}".format(boottime_csv))
    csv_headers = ['Release','ImageID','ImageName','KernelVersion','Region','Arch','InstanceType','FirstLaunchTIme','RebootTime','Stop-StartTime','Comments','Date']
    if not os.path.exists(boottime_csv):
        with FileLock(boottime_csv + '.lock'):
            test_instance.log.info("Create new {}".format(boottime_csv))
            with open(boottime_csv, 'w+') as fh:
                csv_data = csv.DictWriter(fh, csv_headers)
                csv_data.writeheader()
    with FileLock(boottime_csv + '.lock'):
        with open(boottime_csv, 'a+') as fh:
            csv_data = csv.DictWriter(fh, csv_headers)
            csv_data.writerow(test_instance.tmp_data.get('BootTime'))

    if float(boottime) > float(test_instance.params['max_reboot_time']):
        test_instance.fail('boot time {} over expected {}'.format(boottime, test_instance.params['max_reboot_time']))
    else:
        test_instance.log.info('boot time {} within expected {}'.format(boottime, test_instance.params['max_reboot_time']))
        