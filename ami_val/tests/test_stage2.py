import os
import sys
import time
import json
from ami_val.libs.utils_lib import run_cmd
import ami_val

def test_stage2_check_ha_specific(test_instance):
    if 'HA' not in test_instance.info['name']:
        test_instance.skipTest('only run in HA AMIs')
    else:
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