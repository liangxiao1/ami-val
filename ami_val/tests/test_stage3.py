import os
import sys
import time
import json
from ami_val.libs.utils_lib import run_cmd
import ami_val

def test_stage3_check_selinux(test_instance):
    '''
    SELinux should be in enforcing/targeted mode
    '''
    out = run_cmd(test_instance, 'uname -r', msg='get kernel version')
    if 'SAP' in test_instance.info['name']:
        test_instance.log.info('SAP AMIs found')
        run_cmd(test_instance, 'sudo getenforce',expect_kw='Permissive', msg='check selinux current mode is Permissive')
        run_cmd(test_instance, 'sudo cat /etc/sysconfig/selinux',expect_kw='SELINUX=permissive,SELINUXTYPE=targeted', msg='check selinux current setting')
        if 'el7' not in out and 'el6' not in out:
            # el7 and el6 do not have setenforce installed by default, do not try to change its setting
            run_cmd(test_instance, 'sudo setenforce Enforcing && getenforce',expect_kw='Enforcing', msg='try to change to enforcing mode')
            run_cmd(test_instance, 'sudo setenforce Permissive && getenforce',expect_kw='Permissive', msg='try to change to permissive mode')
    else:
        selinux_mode = 'Enforcing'
        run_cmd(test_instance, 'sudo getenforce',expect_kw='Enforcing', msg='check selinux current mode is Enforcing')
        run_cmd(test_instance, 'sudo cat /etc/sysconfig/selinux',expect_kw='SELINUX=enforcing,SELINUXTYPE=targeted', msg='check selinux current setting')
        if 'el7' not in out and 'el6' not in out:
            # el7 and el6 do not have setenforce installed by default, do not try to change its setting
            run_cmd(test_instance, 'sudo setenforce Permissive && getenforce',expect_kw='Permissive', msg='try to change to permissive mode')
            run_cmd(test_instance, 'sudo setenforce Enforcing && getenforce',expect_kw='Enforcing', msg='try to change to enforcing mode')

def test_stage3_check_yum_repoinfo(test_instance):
    if 'ATOMIC' in test_instance.info['name'].upper():
        test_instance.skipTest('skip in Atomic AMIs')
    cmd = "sudo yum repoinfo"
    run_cmd(test_instance, cmd, expect_ret=0, timeout=1200, msg='try to get repo info')


def test_stage3_test_yum_package_install(test_instance):
    if 'ATOMIC' in test_instance.info['name'].upper():
        test_instance.skipTest('skip in Atomic AMIs')
    run_cmd(test_instance, "sudo yum clean all", expect_ret=0, timeout=180)
    run_cmd(test_instance, "sudo yum repolist", expect_ret=0, timeout=1200)
    run_cmd(test_instance, "sudo yum check-update", timeout=1200)
    run_cmd(test_instance, "sudo yum search zsh", expect_ret=0, timeout=180)
    run_cmd(test_instance, "sudo yum -y install zsh", expect_ret=0, timeout=180)
    run_cmd(test_instance, r"sudo rpm -q --queryformat '%{NAME}' zsh", expect_ret=0)
    run_cmd(test_instance, "sudo rpm -e zsh", expect_ret=0)

    if 'SAP' in test_instance.info['name'].upper() and '6.5' in test_instance.info['name']:
        test_instance.log.info("Below is specified for SAP AMIs")
        run_cmd(test_instance, "sudo tuned-profiles-sap-hana", expect_ret=0, timeout=180)
        run_cmd(test_instance, r"sudo rpm -q --queryformat '%{NAME}' tuned-profiles-sap-hana", expect_ret=0)
        run_cmd(test_instance, "sudo rpm -e zsh", expect_ret=0)

def test_stage3_test_yum_group_install(test_instance):
    if 'ATOMIC' in test_instance.info['name'].upper():
        test_instance.skipTest('skip in Atomic AMIs')
    cmd = "sudo yum -y groupinstall 'Development tools'"
    run_cmd(test_instance, cmd, expect_ret=0, timeout=1200, msg='try to install Development tools group')
    run_cmd(test_instance, 'sudo rpm -q glibc-devel', expect_ret=0, msg='try to check installed pkg')

