import os
import sys
import time
import json
from ami_val.libs.utils_lib import run_cmd

def test_stage1_check_bash_history(test_instance):
    for user in ['ec2-user', 'root']:
        cmd = 'sudo cat ~{}/.bash_history'.format(user)
        run_cmd(test_instance, cmd, expect_not_ret='0', msg='check bash history does not exist in fresh AMI')

def test_stage1_check_chrony_aws(test_instance):
    '''
    rhbz: 1679763 [RFE] AWS AMI - Add Amazon Timesync Service
    '''
    run_cmd(test_instance, "sudo cat /etc/chrony.conf", expect_ret=0, expect_kw='server 169.254.169.123', msg='check chrony points to Amazon Time Sync service')

def test_stage1_check_cmdline_console(test_instance):
    '''
    console output shoud be redirected to serial for for hvm instances
    '''
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='console=ttyS0', msg='check serial console is redirected to ttyS0')

def test_stage1_check_cmdline_crashkernel(test_instance):
    '''
    crashkernel should be enabled in image
    '''
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='crashkernel=auto', msg='check crashkernel is enabled')

def test_stage1_check_cmdline_ifnames(test_instance):
    '''
    rhbz: 1859926
    ifnames should be specified
    https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
    '''
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='net.ifnames=0', msg='check ifnames is specified')

def test_stage1_check_cmdline_nouveau(test_instance):
    '''
    rhbz: 1645772
    nouveau should be disabled
    '''
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='rd.blacklist=nouveau', msg='check nouveau is in blacklist')

def test_stage1_check_cmdline_nvme_io_timeout(test_instance):
    '''
    rhbz: 1732506
    change default /sys/module/nvme_core/parameters/io_timeout from 30 to 4294967295
    '''
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='nvme_core.io_timeout=4294967295', msg='checking cmdline')
    out = run_cmd(test_instance, 'sudo lsblk')
    if 'nvme' in out:
        run_cmd(test_instance, "sudo cat /sys/module/nvme_core/parameters/io_timeout", expect_ret=0, expect_kw='4294967295', msg='check actual value')

def test_stage1_check_cmdline_rhgb_quiet(test_instance):
    '''
    rhbz: 1122300
    check no "rhgb" and "quiet" in /proc/cmdline
    '''
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw='rhgb,quiet', msg='check no rhgb and quiet in boot cmd')

def test_stage1_check_cpu_num(test_instance):
    '''
    check the number of cpu cores available
    '''
    cpucount = test_instance.vm.get_cpu_count()
    cmd = "sudo cat /proc/cpuinfo | grep '^processor' | wc -l"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw=str(cpucount), msg='check online cpu match spec define')

def test_stage1_check_inittab(test_instance):
    '''
    check default runlevel or systemd target
    '''
    is_systemd = run_cmd(test_instance, 'rpm -q systemd > /dev/null && echo True || echo False')
    test_instance.log.info("Is systemd system:{}".format(is_systemd))
    if 'True' in is_systemd:
        run_cmd(test_instance, "sudo readlink -f /etc/systemd/system/default.target", expect_ret=0, expect_kw='/lib/systemd/system/multi-user.target', 
            msg='check default runlevel or systemd target')
    else:
        run_cmd(test_instance, "sudo grep '^id:' /etc/inittab", expect_ret=0, expect_kw='id:3:initdefault', 
            msg='check default runlevel or systemd target')
        out = run_cmd(test_instance, 'uname -r')
        if 'el5' in out:
            run_cmd(test_instance, "grep '^si:' /etc/inittab", expect_kw="si::sysinit:/etc/rc.d/rc.sysinit")

def test_stage1_check_nameserver(test_instance):
    '''
    check if DNS resolving works
    '''
    run_cmd(test_instance, "ping -c 5 google-public-dns-a.google.com", expect_ret=0, msg='check if DNS resolving works')

def test_stage1_check_pkg_signed(test_instance):
    '''
    check no pkg signature is none,
    and check that specified gpg keys are installed
    '''
    cmd = "sudo rpm -q gpg-pubkey|wc -l"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw='2', msg='check gpg-pubkey installed')
    cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -v gpg-pubkey"
    run_cmd(test_instance, cmd, expect_ret=0, expect_not_kw='none', msg='check no pkg signature is none')
    cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -v gpg-pubkey|awk -F' ' '{print $NF}'|sort|uniq|wc -l"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw='1', msg='check use only one keyid')

def test_stage1_check_rhui_pkg(test_instance):
    aminame = test_instance.info['name']
    if 'HA' in aminame:
        test_instance.log.info('HA AMI found')
        rhui_pkg = 'rh-amazon-rhui-client-ha'
    elif 'SAP' in aminame:
        test_instance.log.info('SAP AMI found')
        # rhel7.9 does not have e4s repo, but rhel7.7, 8.2 have
        # so do not check e4s as I do not know which should have either.
        rhui_pkg = 'rh-amazon-rhui-client-sap-bundle'
        #rhui_pkg = 'rh-amazon-rhui-client-sap-bundle-e4s'
    else:
        test_instance.log.info('RHEL AMI found')
        rhui_pkg = 'rh-amazon-rhui-client'
    cmd = 'sudo rpm -qa|grep rhui'
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw=rhui_pkg,msg='get rhui pkg version')

def test_stage1_check_root_is_locked(test_instance):
    """
    Root account should be locked
    """
    aminame = test_instance.info['name']
    if 'ATOMIC' in aminame.upper():
        test_instance.log.info('Atomic AMI found')
        cmd = 'sudo passwd -S root | grep -q Alternate'
    else:
        test_instance.log.info('RHEL AMI found')
        cmd = 'sudo passwd -S root | grep -q LK'
    run_cmd(test_instance, cmd, expect_ret=0, msg='check root is locked')

def test_stage1_check_shells(test_instance):
    """
    Check for bash/nologin shells in /etc/shells
    """
    run_cmd(test_instance, 'sudo cat /etc/shells', expect_kw='/bin/bash', msg='check /bin/bash in /etc/shells')


def test_stage1_check_sshd(test_instance):
    '''
    sshd service shoud be on, password authentication shoud be disabled
    '''
    is_systemd = run_cmd(test_instance, 'rpm -q systemd > /dev/null && echo True || echo False')
    test_instance.log.info("Is systemd system:{}".format(is_systemd))
    if 'True' in is_systemd:
        cmd = 'sudo systemctl is-active sshd.service'
        run_cmd(test_instance, cmd, expect_ret=0, msg='check if sshd active')
    cmd = 'sudo cat /etc/ssh/sshd_config'
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw='PasswordAuthentication no', msg='check if password auth disabled')

def test_stage1_check_timezone(test_instance):
    '''
    rhbz: 1187669
    check that the default timezone is set to UTC
    '''
    run_cmd(test_instance, 'date', expect_kw='UTC', msg='check timezone is set to UTC')

def test_stage1_check_username(test_instance):
    for user in ['fedora', 'cloud-user']:
        cmd = 'sudo cat /etc/passwd|grep {}'.format(user)
        run_cmd(test_instance, cmd, expect_not_ret='0', msg='check no {} user in fresh AMI'.format(user))
    run_cmd(test_instance, 'whoami', expect_kw=test_instance.vm.ssh_username, msg='check default user')
    run_cmd(test_instance, 'uname -a', msg='get kernel version')