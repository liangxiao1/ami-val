import os
import re
import sys
import time
import json
from ami_val.libs.utils_lib import run_cmd, get_product_id
import ami_val

def test_stage2_check_auditd(test_instance):
    """
    Check auditd:
    - service should be on
    - config files shoud have specified checksums
    """
    if 'ATOMIC' in test_instance.info['name'].upper():
        test_instance.skipTest('skip run in Atomic AMIs')
    if 'RHEL-6' in test_instance.info['name'].upper():
        cmd = 'sudo service auditd status'
    else:
        cmd = 'sudo systemctl is-active auditd'
    run_cmd(test_instance, cmd, expect_ret=0, msg='check if auditd service is active')
    out = run_cmd(test_instance, 'sudo cat /etc/redhat-release', expect_ret=0, msg='get release name')
    if 'release 8' in out:
        auditd_checksum = '7bfa16d314ddb8b96a61a7f617b8cca0'
        auditd_rules_checksum = '795528bd4c7b4131455c15d5d49991bb'
    elif 'release 7' in out:
        # 7.5 onward
        auditd_checksum = '29f4c6cd67a4ba11395a134cf7538dbd'
        auditd_rules_checksum = 'f1c2a2ef86e5db325cd2738e4aa7df2c'
    elif 'release 6' in out:
        # 6.9 onward
        auditd_checksum = '306e13910db5267ffd9887406d43a3f7'
        auditd_sysconf_checksum = '0825f77b49a82c5d75bcd347f30407ab'
        run_cmd(test_instance, 'sudo md5sum /etc/sysconfig/auditd', expect_kw=auditd_sysconf_checksum)
    else:
        test_instance.skipTest('skip run in el5 and earlier than 6.9, 7.5. el9 will be added')

    run_cmd(test_instance, 'sudo md5sum /etc/audit/auditd.conf', expect_kw=auditd_checksum)
    if 'release 6' not in out:
        run_cmd(test_instance, 'sudo md5sum /etc/audit/audit.rules', expect_kw=auditd_rules_checksum)

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
    #bz: 1959963
    if 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in SAP AMIs')
    expected_cfg =  '@sapsys    hard    nofile   65536,\
@sapsys    soft    nofile   65536,\
@dba       hard    nofile   65536,\
@dba       soft    nofile   65536,\
@sapsys    hard    nproc    unlimited,\
@sapsys    soft    nproc    unlimited,\
@dba       hard    nproc    unlimited,\
@dba       soft    nproc    unlimited'
    cmd = 'sudo cat /etc/security/limits.d/99-sap.conf'
    run_cmd(test_instance, cmd, expect_kw=expected_cfg, msg='check /etc/security/limits.d/99-sap.conf')

def test_stage2_check_sap_sysctl(test_instance):
    #bz: 1959962
    if 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in SAP AMIs')
    expected_cfg = 'kernel.pid_max = 4194304,vm.max_map_count = 2147483647'
    cmd = 'sudo cat /etc/sysctl.d/sap.conf'
    run_cmd(test_instance, cmd, expect_kw=expected_cfg, msg='check /etc/sysctl.d/sap.conf')

def test_stage2_check_sap_tmpfiles(test_instance):
    #bz: 1959979
    if 'SAP' not in test_instance.info['name']:
        test_instance.skipTest('only run in SAP AMIs')
    expected_cfg =  'x /tmp/.sap*,x /tmp/.hdb*lock,x /tmp/.trex*lock'
    cmd = 'sudo cat /etc/tmpfiles.d/sap.conf'
    run_cmd(test_instance, cmd, expect_kw=expected_cfg, msg='check /etc/tmpfiles.d/sap.conf')

def test_stage2_check_sap_tuned(test_instance):
    #bz: 1959962
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
        