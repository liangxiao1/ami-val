import os
import sys
import time
import json
from ami_val.libs.utils_lib import run_cmd, get_product_id, is_fedora
import ami_val
import re

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
    if 'RHEL-6' in test_instance.info['name'].upper():
        test_instance.skipTest('skip in el6 as no yum repoinfo subcommand')
    cmd = "sudo yum repoinfo"
    if is_fedora(test_instance):
        # fedora updates repo Repo-pkgs is 0 maybe because of no updates in developing
        run_cmd(test_instance, cmd, expect_ret=0, timeout=1200, msg='try to get repo info')
    else:
        run_cmd(test_instance, cmd, expect_ret=0, expect_not_kw='Repo-pkgs          : 0', timeout=1200, msg='try to get repo info')

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

def test_stage3_test_subscription_manager_auto(test_instance):
    '''
    bz: 1932802, 1905398
    '''
    if 'ATOMIC' in test_instance.info['name'].upper():
        test_instance.skipTest('skip in Atomic AMIs')
    if is_fedora(test_instance):
        test_instance.skipTest('skip run in Fedora AMIs')
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.4'):
        test_instance.skipTest('skip in earlier than el8.4')

    cmd = "sudo subscription-manager config"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw="auto_registration = 1,manage_repos = 0", msg='try to check subscription-manager config')
    cmd = "sudo systemctl is-enabled rhsmcertd"
    run_cmd(test_instance, cmd, expect_ret=0, msg='try to check rhsmcertd enabled')
    cmd = "sudo subscription-manager config --rhsmcertd.auto_registration_interval=1"
    run_cmd(test_instance, cmd, expect_ret=0, msg='try to change rhsmcertd.auto_registration_interval from 60min to 1min')
    cmd = "sudo systemctl restart rhsmcertd"
    run_cmd(test_instance, cmd, expect_ret=0, msg='restart rhsmcertd')
    start_time = time.time()
    timeout = 600
    interval = 60
    while True:
        cmd = 'sudo cat /var/log/rhsm/rhsmcertd.log'
        run_cmd(test_instance, cmd, msg='try to check rhsmcertd.log')
        cmd = 'sudo cat /var/log/rhsm/rhsm.log'
        run_cmd(test_instance, cmd, msg='try to check rhsm.log')
        cmd = "sudo subscription-manager identity"
        out = run_cmd(test_instance, cmd, msg='try to check subscription identity')
        cmd = "sudo subscription-manager list --installed"
        out = run_cmd(test_instance, cmd, msg='try to list currently installed on the system')
        cmd = "sudo subscription-manager status"
        out = run_cmd(test_instance, cmd, msg='try to check subscription status')
        if 'Red Hat Enterprise Linux' in out or 'Simple Content Access' in out:
            test_instance.log.info("auto subscription registered completed")
            cmd = "sudo insights-client --register"
            run_cmd(test_instance, cmd, msg='check if insights-client can register successfully')
            break
        end_time = time.time()
        if end_time - start_time > timeout:
            cmd = "sudo insights-client --register"
            run_cmd(test_instance, cmd, msg='check if insights-client can register successfully')
            test_instance.fail("timeout({}s) to wait auto subscription registered completed".format(timeout))
        test_instance.log.info('wait {}s and try to check again, timeout {}s'.format(interval, timeout))
        time.sleep(interval)

