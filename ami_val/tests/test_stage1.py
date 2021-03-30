import os
import sys
import time
import json
import re
from ami_val.libs.utils_lib import run_cmd, is_arch

def test_stage1_check_bash_history(test_instance):
    for user in ['ec2-user', 'root']:
        cmd = 'sudo cat ~{}/.bash_history'.format(user)
        run_cmd(test_instance, cmd, expect_not_ret='0', msg='check bash history does not exist in fresh AMI')


def test_stage1_check_cds_hostnames(test_instance):
    '''
    check cds hostname
    '''
    rhui_cds_hostnames = ["rhui2-cds01.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui2-cds02.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui3-cds01.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui3-cds02.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui3-cds03.{}.aws.ce.redhat.com".format(test_instance.info['region'])]
    for cds in rhui_cds_hostnames:
        cmd = "sudo getent hosts {}".format(cds)
        run_cmd(test_instance, cmd, expect_ret=0, msg='check {}'.format(cds))

def test_stage1_check_chrony_aws(test_instance):
    '''
    rhbz: 1679763 [RFE] AWS AMI - Add Amazon Timesync Service
    '''
    run_cmd(test_instance, "sudo cat /etc/chrony.conf", expect_ret=0, expect_kw='server 169.254.169.123', msg='check chrony points to Amazon Time Sync service')

def test_stage1_check_cloud_firstboot(test_instance):
    '''
    check that rh-cloud-firstboot is disabled
    '''
    run_cmd(test_instance, "sudo chkconfig --list rh-cloud-firstboot", expect_kw='3:off', msg='check that rh-cloud-firstboot is disabled')
    run_cmd(test_instance, "sudo cat /etc/sysconfig/rh-cloud-firstboot", expect_kw='RUN_FIRSTBOOT=NO', msg='check that rh-cloud-firstboot is configured')

def test_stage1_check_cmdline_console(test_instance):
    '''
    console output shoud be redirected to serial for for hvm instances
    '''
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='console=ttyS0', msg='check serial console is redirected to ttyS0')

def test_stage1_check_cmdline_crashkernel(test_instance):
    '''
    crashkernel should be enabled in image
    '''
    aminame = test_instance.info['name']
    if 'RHEL-6' in aminame:
        run_cmd(test_instance, "sudo service kdump status")
        run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw='crashkernel', msg='crashkernel not required as xen kdump unsupported')
    else:
        run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='crashkernel=auto', msg='check crashkernel is enabled')

def test_stage1_check_cmdline_ifnames(test_instance):
    '''
    rhbz: 1859926
    ifnames should be specified
    https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
    '''
    aminame = test_instance.info['name']
    if 'RHEL-6' in aminame:
        test_instance.skipTest('not required in el6')
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='net.ifnames=0', msg='check ifnames is specified')

def test_stage1_check_cmdline_nouveau(test_instance):
    '''
    rhbz: 1645772
    nouveau should be disabled
    '''
    aminame = test_instance.info['name']
    if 'RHEL-6' in aminame:
        test_instance.skipTest('not required in el6')
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='rd.blacklist=nouveau', msg='check nouveau is in blacklist')

def test_stage1_check_cmdline_nvme_io_timeout(test_instance):
    '''
    rhbz: 1732506
    change default /sys/module/nvme_core/parameters/io_timeout from 30 to 4294967295
    '''
    aminame = test_instance.info['name']
    if 'RHEL-6' in aminame:
        test_instance.skipTest('not required in el6')
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

def test_stage1_check_cpu_flags(test_instance):
    '''
    rhbz: 1061348
    check various cpu flags
    '''
    is_arch(test_instance, arch='x86_64', action='cancel')
    cmd = "sudo cat /proc/cpuinfo"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw='avx,xsave', msg='check avx and xsave flags')

def test_stage1_check_cpu_num(test_instance):
    '''
    check the number of cpu cores available
    '''
    cpucount = test_instance.vm.get_cpu_count()
    cmd = "sudo cat /proc/cpuinfo | grep '^processor' | wc -l"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw=str(cpucount), msg='check online cpu match spec define')

def test_stage1_check_ena_set_in_image(test_instance):
    '''
    check the number of cpu cores available
    '''
    aminame = test_instance.info['name']
    if aminame.startswith(('RHEL-6','RHEL-7.0','RHEL-7.1','RHEL-7.2','RHEL-7.3')):
        if test_instance.vm.is_image_ena_enabled():
            test_instance.fail("Image ena_support is enabled as unexpected before RHEL-7.4")
        else:
            test_instance.log.info("Image ena_support is disabled as expected before RHEL-7.4")
    else:
        if not test_instance.vm.is_image_ena_enabled():
            test_instance.fail("Image ena_support is disabled as unexpected after RHEL-7.4")
        else:
            test_instance.log.info("Image ena_support is enabled as expected after RHEL-7.4")

def test_stage1_check_firewalld(test_instance):
    '''
    firewalld is not required in cloud because there is security group.
    '''
    check_cmd = "sudo cat /etc/redhat-release"
    output = run_cmd(test_instance,check_cmd, expect_ret=0, msg='check release name')
    product_id = re.findall('\d.\d', output)[0]
    test_instance.log.info("Get product id: {}".format(product_id))
    if product_id < '7.0':
        cmd = "sudo chkconfig --list ip6tables"
        run_cmd(test_instance,cmd, expect_ret=0, expect_kw='3:off', msg='check ip6tables is disabled')
        cmd = "sudo chkconfig --list iptables"
        run_cmd(test_instance,cmd, expect_ret=0, expect_kw='3:off', msg='check iptables is disabled')
    else:
        cmd = 'sudo rpm -q firewalld'
        run_cmd(test_instance,cmd, expect_not_ret='1', msg='check firewalld is not installed')

def test_stage1_check_grub(test_instance):
    '''
    Check grub config:
    - /boot/grub/menu.lst exists
    - /boot/grub/menu.lst is symlink for /boot/grub/grub.conf
    - hard drive is not (hd0,0) for paravirtual
    '''
    aminame = test_instance.info['name']
    if not aminame.startswith(('RHEL-6')):
        test_instance.skipTest('only run in el5, el6')
    cmd = 'sudo readlink -e /boot/grub/menu.lst'
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw="/boot/grub/grub.conf", 
        msg='check /boot/grub/menu.lst is symlink for /boot/grub/grub.conf')
    cmd = 'sudo cat /boot/grub/grub.conf'
    out = run_cmd(test_instance, cmd, expect_ret=0, msg='get grub.conf')
    if r"hd0,0" not in out:
        test_instance.fail("'hd0,0' not found in grub.conf")

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

def test_stage1_check_instance_identity(test_instance):
    '''
    try to fetch instance identity from EC2 and compare with expectation
    '''
    aminame = test_instance.info['name']
    cmd = 'curl http://169.254.169.254/latest/dynamic/instance-identity/document'
    output = run_cmd(test_instance, cmd, expect_ret=0, msg='get instance identity data')
    instance = json.loads(output)
    if instance['imageId'] != test_instance.info['ami']:
        test_instance.fail("instance ami-id({}) does not match tested AMIs({})".format(instance['imageId'], test_instance.info['ami']))
    else:
        test_instance.log.info("instance ami-id({}) match tested AMIs({})".format(instance['imageId'], test_instance.info['ami']))
    if instance['region'] != test_instance.info['region']:
        test_instance.fail("instance region({}) does not match tested AMIs({})".format(instance['region'], test_instance.info['region']))
    else:
        test_instance.log.info("instance region({}) match tested AMIs({})".format(instance['region'], test_instance.info['region']))
    if instance['architecture'] != test_instance.info['release']['arch']:
        test_instance.fail("instance arch({}) does not match tested AMIs({})".format(instance['architecture'], test_instance.info['release']['arch']))
    else:
        test_instance.log.info("instance arch({}) match tested AMIs({})".format(instance['architecture'], test_instance.info['release']['arch']))

    if 'HA' in aminame and 'Access2' not in aminame:
        # RHELDST-4222, on-demand (hourly) has the billing code for RHEL and for HA
        billingcodes = ['bp-79a54010', 'bp-6fa54006']
    elif 'Hourly2' in aminame:
        billingcodes = ['bp-6fa54006']
    elif 'Access2' in aminame:
        # Cloud Access billing code, means don't charge for the OS (so it can apply to anything cloud Access)
        billingcodes = ['bp-63a5400a']
    for billingcode in billingcodes:
        if billingcode not in instance['billingProducts']:
            test_instance.fail("expected({}) not found in instance billingcode({})".format(billingcode, instance['billingProducts']))
        else:
            test_instance.log.info("expected({}) found in instance billingcode({}).".format(billingcode, instance['billingProducts']))

def test_stage1_check_nameserver(test_instance):
    '''
    check if DNS resolving works
    '''
    run_cmd(test_instance, "ping -c 5 google-public-dns-a.google.com", expect_ret=0, msg='check if DNS resolving works')

def test_stage1_check_network_driver(test_instance):
    '''
    if ena network device found, eth0 should use ena as default driver
    if vf network device found, eth0 should use ixgbevf as default driver
    if others, eth0 should use vif as default driver
    if it is not a xen instance, ena should be used.
    '''
    cmd = 'sudo lspci'
    pci_out = run_cmd(test_instance, cmd, expect_ret=0, msg='get pci devices')
    ethtool_cmd = 'sudo ethtool -i eth0'
    if 'ENA' in pci_out:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='ena', msg='check if eth0 is using ena driver')
    elif 'Virtual Function' in pci_out:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='ixgbevf', msg='check if eth0 is using ixgbevf driver')
    else:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='vif', msg='check if eth0 is using vif driver')
    cmd = 'sudo lscpu'
    cpu_out = run_cmd(test_instance, cmd, expect_ret=0, msg='get cpu info')
    if 'Xen' not in cpu_out:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='ena', msg='ena must used in KVM, aarch64 and metal instances')

def test_stage1_check_network_ipv6(test_instance):
    '''
    check for networking setup
    '''
    cmd = "curl http://169.254.169.254/latest/meta-data/network/interfaces/macs"
    mac = run_cmd(test_instance, cmd, expect_ret=0, msg='get mac address')
    cmd = "{}/{}/ipv6s".format(cmd, mac)
    ipv6s = run_cmd(test_instance, cmd, msg='get ipv6 address')
    if 'Not Found' in ipv6s:
        test_instance.skipTest('no ipv6 enabled in this subnet')
    cmd = "sudo ip addr show eth0"
    run_cmd(test_instance, cmd, expect_kw=ipv6s, msg='check if ipv6 address appear in eth0')

def test_stage1_check_network_setup(test_instance):
    '''
    check for networking setup
    '''

    run_cmd(test_instance, 'grep "^NETWORKING=yes" /etc/sysconfig/network', expect_ret=0, msg='check /etc/sysconfig/network')
    run_cmd(test_instance, 'egrep "^DEVICE=(|\\\")eth0(|\\\")" /etc/sysconfig/network-scripts/ifcfg-eth0', expect_ret=0, msg='check eth0 used')

def test_stage1_check_no_avc_denials(test_instance):
    '''
    check there is no avc denials (selinux)
    '''
    cmd = "x=$(sudo ausearch -m avc 2>&1 &); echo $x"
    run_cmd(test_instance, cmd, expect_kw='no matches', msg='check no avc denials')

def test_stage1_check_numa(test_instance):
    '''
    check if NUMA is enabled on supported machine
    '''
    cmd = "sudo lscpu|grep -i 'NUMA node(s)'|awk -F' ' '{print $NF}'"
    numa_nodes = run_cmd(test_instance, cmd, expect_ret=0, msg='get numa nodes')
    run_cmd(test_instance, 'dmesg|grep -i numa', expect_ret=0, msg='get numa info')
    cmd = "sudo dmesg|grep -i 'No NUMA'|wc -l"
    out = run_cmd(test_instance, cmd, expect_ret=0)
    if int(numa_nodes) > 1:
        if int(out) == 1:
            test_instance.fail("numa seems not enabled as expected")
        else:
            test_instance.log.info("numa seems enabled as expected")
    else:
        test_instance.log.info("only 1 node found")

def test_stage1_check_pkg_signed(test_instance):
    '''
    check no pkg signature is none,
    and check that specified gpg keys are installed
    '''
    cmd = "sudo rpm -qa|grep gpg-pubkey"
    run_cmd(test_instance, cmd, expect_ret=0, msg='check gpg-pubkey installed')
    cmd = "sudo rpm -q gpg-pubkey|wc -l"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw='2', msg='check 2 gpg-pubkey installed')
    cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -v gpg-pubkey"
    run_cmd(test_instance, cmd, expect_ret=0, expect_not_kw='none', msg='check no pkg signature is none')
    cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -v gpg-pubkey|awk -F' ' '{print $NF}'|sort|uniq|wc -l"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw='1', msg='check use only one keyid')

def test_stage1_check_product_id(test_instance):
    '''
    bz: 1938930
    issue: RHELPLAN-60817
    check if product id matches /etc/redhat-release
    '''
    check_cmd = "sudo cat /etc/redhat-release"
    output = run_cmd(test_instance,check_cmd, expect_ret=0, msg='check release name')
    product_id = re.findall('\d.\d', output)[0]
    test_instance.log.info("Get product id: {}".format(product_id))
    cmd = 'sudo rpm -qa|grep redhat-release'
    run_cmd(test_instance,cmd, cancel_ret='0', msg='get redhat-release-server version')
    cmd = 'sudo rct cat-cert /etc/pki/product-default/*.pem'
    run_cmd(test_instance,cmd, expect_ret=0, expect_kw="Version: {}".format(product_id), msg='check product certificate')

def test_stage1_check_rhel_version(test_instance):
    '''
    check if rhel provider matches /etc/redhat-release and ami name
    '''
    aminame = test_instance.info['name']
    if 'HA' in aminame:
        test_instance.skipTest('not run in HA AMIs')
    if 'SAP' in aminame:
        test_instance.skipTest('not run in SAP AMIs')
    if 'Atomic' in aminame:
        test_instance.skipTest('not run in Atomic AMIs')
    check_cmd = "sudo cat /etc/redhat-release"
    output = run_cmd(test_instance,check_cmd, expect_ret=0, msg='check release name')
    product_id = re.findall('\d.\d', output)[0]
    cmd = "sudo rpm -q --qf '%{VERSION}' --whatprovides redhat-release"
    run_cmd(test_instance,cmd, expect_kw=product_id, msg='check redhat-release version match')
    if product_id not in aminame:
        test_instance.fail('{} not found in ami name: {}'.format(product_id, aminame))
    test_instance.log.info('{} found in ami name: {}'.format(product_id, aminame))

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

def test_stage1_check_yum_plugins(test_instance):
    '''
    bz: 1932802
    earlier than RHEL-8.4 yum plugin product-id and subscription-manager should be disabled by default.
    '''
    if 'ATOMIC' in test_instance.info['name'].upper():
        test_instance.skipTest('skip run in Atomic AMIs')
    check_cmd = "sudo cat /etc/redhat-release"
    output = run_cmd(test_instance,check_cmd, expect_ret=0, msg='check release name')
    product_id = re.findall('\d.\d', output)[0]
    test_instance.log.info("Get product id: {}".format(product_id))
    if product_id < '8.4':
        expect_kw="enabled=0"
        status = 'disabled'
    else:
        expect_kw="enabled=1"
        status = 'enabled'
    cmd = 'sudo cat /etc/yum/pluginconf.d/product-id.conf'
    run_cmd(test_instance,cmd, expect_ret=0, expect_kw=expect_kw, msg='check yum product-id plugin is {}'.format(status))
    cmd = 'sudo cat /etc/yum/pluginconf.d/subscription-manager.conf'
    run_cmd(test_instance,cmd, expect_ret=0, expect_kw=expect_kw, msg='check yum subscription-manager plugin is {}'.format(status))