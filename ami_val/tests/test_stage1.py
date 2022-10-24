import os
import sys
import time
import json
import re
import glob
import filecmp
import difflib
import datetime
from ami_val.libs.utils_lib import run_cmd, is_arch, get_product_id, is_fedora, is_cmd_exist, getboottime

def test_stage1_check_bash_history(test_instance):
    for user in ['ec2-user', 'root']:
        cmd = 'sudo cat ~{}/.bash_history'.format(user)
        run_cmd(test_instance, cmd, expect_not_ret='0', msg='check bash history does not exist in fresh AMI')

def test_stage1_check_bootime_launch(test_instance):
    '''
    check first launch boot time.
    can change pass criteria in cfg ami-val.yaml, default is 50s.
    rhbz: 1862930
    '''

    test_instance.tmp_data['BootTime'] = {''}
    boottime = getboottime(test_instance)
    test_instance.tmp_data['BootTime'] = {'FirstLaunchTIme':boottime}
    test_instance.tmp_data['BootTime']['ImageID'] = test_instance.vm.ami_id
    test_instance.tmp_data['BootTime']['ImageName'] = test_instance.info['name']
    test_instance.tmp_data['BootTime']['Release'] = test_instance.info['release'].get('version')
    out = run_cmd(test_instance, 'uname -r', expect_ret=0, msg='get kernel version')
    test_instance.tmp_data['BootTime']['KernelVersion'] = out.strip('\n')
    test_instance.tmp_data['BootTime']['Region'] = test_instance.info.get('region')
    out = run_cmd(test_instance, 'uname -i', expect_ret=0, msg='get arch')
    test_instance.tmp_data['BootTime']['Arch'] = out.strip('\n')
    test_instance.tmp_data['BootTime']['InstanceType'] = test_instance.vm.res_type
    test_instance.tmp_data['BootTime']['Date'] = datetime.datetime.today().strftime('%Y-%m-%d')

    if float(boottime) > float(test_instance.params['max_boot_time']):
        test_instance.fail('boot time {} over expected {}'.format(boottime, test_instance.params['max_boot_time']))
    else:
        test_instance.log.info('boot time {} within expected {}'.format(boottime, test_instance.params['max_boot_time']))

def test_stage1_check_cds_hostnames(test_instance):
    '''
    check cds hostname
    '''
    rhui_cds_hostnames = [
                          "rhui3-cds01.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui3-cds02.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui3-cds03.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui4-cds01.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui4-cds02.{}.aws.ce.redhat.com".format(test_instance.info['region']),
                          "rhui4-cds03.{}.aws.ce.redhat.com".format(test_instance.info['region'])]
    for cds in rhui_cds_hostnames:
        #there is no rhui in us-gov regions at all - all the content requests are redirected to closest standard regions
        cds_name = cds.replace('-gov','')
        cmd = "sudo getent hosts {}".format(cds_name)
        run_cmd(test_instance, cmd, expect_ret=0, msg='check {}'.format(cds_name))

def test_stage1_check_cloudinit_cfg_growpart(test_instance):
        '''
        bz: 966888
        des: make sure there is growpart in cloud_init_modules group in "/etc/cloud/cloud.cfg"
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        run_cmd(test_instance,
                    cmd,
                    expect_ret=0,
                    expect_kw='- growpart',
                    msg='check /etc/cloud/cloud.cfg to make sure there is growpart in cloud_init_modules(bz966888)')

def test_stage1_check_cloudinit_cfg_no_wheel(test_instance):
        '''
        bz: 1549638
        cm: 01965459
        polarion_id:
        des: make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        run_cmd(test_instance,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='wheel',
                    msg='check /etc/cloud/cloud.cfg to make sure no wheel in default_user group(bz1549638)')

def test_stage1_check_chrony_aws(test_instance):
    '''
    rhbz: 1679763 [RFE] AWS AMI - Add Amazon Timesync Service
    # https://access.redhat.com/solutions/5132071
    # https://bugzilla.redhat.com/show_bug.cgi?id=1961156
    '''
    run_cmd(test_instance, "sudo cat /etc/chrony.conf", expect_ret=0, expect_kw='server 169.254.169.123', msg='check chrony points to Amazon Time Sync service')
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.5') and float(product_id) > float('7.9'):
        run_cmd(test_instance, "sudo cat /etc/chrony.conf", expect_ret=0, expect_kw="#leapsectz right/UTC,#pool 2.rhel.pool.ntp.org iburst", msg='check no NTP leap smear incompatibilitye')
    else:
        run_cmd(test_instance, "sudo cat /etc/chrony.conf", expect_ret=0, expect_not_kw="leapsectz right/UTC,pool 2.rhel.pool.ntp.org iburst", msg='check no NTP leap smear incompatibilitye')
    run_cmd(test_instance, "sudo journalctl -u chronyd", expect_ret=0, expect_kw='Selected source 169.254.169.123', msg='check Amazon Time Sync service is in use')

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
    product_id = get_product_id(test_instance)
    if 'RHEL-6' in aminame:
        run_cmd(test_instance, "sudo service kdump status")
        run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw='crashkernel', msg='crashkernel not required as xen kdump unsupported')
    else:
        cmd = "sudo kdumpctl showmem"
        run_cmd(test_instance, cmd, expect_ret=0, msg='list reserved memory')
        if float(product_id) < float('9'):
            expect_kw = 'crashkernel=auto'
            run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw=expect_kw, msg='check crashkernel is enabled')
        else:
            # rhbz: 1942398
            expect_kw = 'crashkernel'
            run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw=expect_kw, expect_not_kw='crashkernel=auto',msg='check crashkernel is enabled')

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

def test_stage1_check_cmdline_iommu_strict(test_instance):
    '''
    rhbz: 1836058
    des: use "iommu.strict=0" in arm AMIs to get better performance
    '''
    aminame = test_instance.info['name']
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.5') and 'Atomic' not in aminame:
        test_instance.skipTest('skip in earlier than el8.4 AMIs')
    option = 'iommu.strict=0'
    if is_arch(test_instance,arch='x86'):
        run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw=option, msg='check no {} in x86 AMIs'.format(option))
    else:
        run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw=option, msg='check {} in arm AMIs'.format(option))

def test_stage1_check_cmdline_max_cstate(test_instance):
    '''
    rhbz: 1961225
    desc: intel_idle.max_cstate=1 processor.max_cstate=1 exists in SAP AMI's /proc/cmdline.
    '''
    aminame = test_instance.info['name']
    expect_kw = "intel_idle.max_cstate=1,processor.max_cstate=1"
    if 'SAP' in test_instance.info['name']:
        run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw=expect_kw, msg='check {} is specified in sap ami'.format(expect_kw))
    else:
        run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw=expect_kw, msg='check {} is not specified in non-sap ami'.format(expect_kw))

def test_stage1_check_cmdline_nouveau(test_instance):
    '''
    rhbz: 1645772
    nouveau should be disabled
    '''
    aminame = test_instance.info['name']
    if 'RHEL-6' in aminame:
        test_instance.skipTest('not required in el6')
    run_cmd(test_instance, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='rd.blacklist=nouveau', msg='check nouveau is in blacklist')
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.5'):
        file_check = '/etc/modprobe.d/blacklist-nouveau.conf'
    else:
        file_check = '/usr/lib/modprobe.d/blacklist-nouveau.conf'
    expect_kw='blacklist nouveau'
    run_cmd(test_instance, "sudo cat {}".format(file_check), expect_ret=0, expect_kw=expect_kw, msg='check "{}" in {}'.format(expect_kw, file_check))

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

def test_stage1_check_dracut_conf_sgdisk(test_instance):
    '''
    des: enable resizing on copied AMIs, added 'install_items+=" sgdisk "' to "/etc/dracut.conf.d/sgdisk.conf"
    '''
    cmd = "rpm -q gdisk"
    run_cmd(test_instance, cmd, expect_ret=0, msg='Check if gdisk is installed')

    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.5'):
        file_check = '/etc/dracut.conf.d/sgdisk.conf'
    else:
        file_check = '/usr/lib/dracut/dracut.conf.d/sgdisk.conf'
    expect_kw='install_items+=" sgdisk "'
    cmd = "sudo cat {}".format(file_check)
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw=expect_kw, msg='check if "{}" is added into {}'.format(expect_kw,file_check))

def test_stage1_check_dracut_conf_xen(test_instance):
    '''
    rhbz: 1849082
    des: add ' xen-netfront xen-blkfront ' to '/etc/dracut.conf.d/xen.conf' in x86 AMIs prior RHEL-8.4.
         using image builder from RHEL-8.5, updated to add ' nvme xen-blkfront ' to '/usr/lib/dracut/dracut.conf.d/ec2.conf'.
         This is not required in arm AMIs and RHEL-7.
    '''
    cmd = "sudo cat /etc/dracut.conf.d/xen.conf"
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8'):
        file_check = '/etc/dracut.conf.d/xen.conf'
        test_instance.skipTest('{} is not required in el7'.format(file_check))
    elif float(product_id) < float('8.5'):
        file_check = '/etc/dracut.conf.d/xen.conf'
        expect_kw=' xen-netfront xen-blkfront '
    else:
        #COMPOSER-1096
        file_check = '/usr/lib/dracut/dracut.conf.d/ec2.conf'
        expect_kw=' nvme xen-blkfront '
    cmd = "sudo cat {}".format(file_check)
    if is_arch(test_instance, arch='x86_64'):
        run_cmd(test_instance, cmd, expect_ret=0, expect_kw=expect_kw, msg='check if "{}" exists in x86 amis'.format(expect_kw))
    else:
        run_cmd(test_instance, cmd, expect_not_ret=0, msg='check no {} in arm amis'.format(file_check))

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
    product_id = get_product_id(test_instance)
    if float(product_id) < float('7.0'):
        cmd = "sudo chkconfig --list ip6tables"
        run_cmd(test_instance,cmd, expect_ret=0, expect_kw='3:off', msg='check ip6tables is disabled')
        cmd = "sudo chkconfig --list iptables"
        run_cmd(test_instance,cmd, expect_ret=0, expect_kw='3:off', msg='check iptables is disabled')
    else:
        cmd = 'sudo rpm -q firewalld'
        run_cmd(test_instance,cmd, expect_not_ret='1', msg='check firewalld is not installed')

def test_stage1_check_grub(test_instance):
    '''
    Check grub config for el5,el6:
    - /boot/grub/menu.lst exists
    - /boot/grub/menu.lst is symlink for /boot/grub/grub.conf
    - hard drive is not (hd0,0) for paravirtual
    Check grub2 config for el8:
    - boot with efi or legacy bios
    - /boot/grub2/grubenv is a symlink for /boot/efi/EFI/redhat/grubenv if boot with efi
    - /boot/grub2/grubenv is a file rather than a link if boot with legacy bios
    Check grub2 config for el9:
    - boot with efi or legacy bios
    - /boot/grub2/grub.cfg exists and /boot/grub2/grubenv is a file if boot with efi
    - /boot/grub2/grubenv is a file rather than a link if boot with legacy bios
    '''
    product_id = get_product_id(test_instance)
    if float(product_id) < float('7'):
        cmd = 'sudo readlink -e /boot/grub/menu.lst'
        run_cmd(test_instance, cmd, expect_ret=0, expect_kw="/boot/grub/grub.conf",
            msg='check /boot/grub/menu.lst is symlink for /boot/grub/grub.conf')
        cmd = 'sudo cat /boot/grub/grub.conf'
        out = run_cmd(test_instance, cmd, expect_ret=0, msg='get grub.conf')
        if r"hd0,0" not in out:
            test_instance.fail("'hd0,0' not found in grub.conf")
    elif float(product_id) > float('7.9'):
        cmd = 'sudo ls /sys/firmware/efi'
        out = run_cmd(test_instance, cmd, msg='check if boot with efi')
        cmd = 'sudo readlink -e /boot/grub2/grubenv'
        if out and 'No such file' not in out:
            if float(product_id) < float('9'):
                run_cmd(test_instance, cmd, expect_ret=0, expect_kw="/boot/efi/EFI/redhat/grubenv",
                        msg='check /boot/grub2/grubenv is symlink for /boot/efi/EFI/redhat/grubenv')
            else:
                run_cmd(test_instance, cmd, expect_ret=0, expect_kw="/boot/grub2/grubenv",
                        msg='check /boot/grub2/grubenv is a file rather than a link')
                run_cmd(test_instance, 'sudo ls /boot/grub2', expect_ret=0, expect_kw="grub.cfg",
                        msg='check for grub.cfg')
        else:
            run_cmd(test_instance, cmd, expect_ret=0, expect_kw="/boot/grub2/grubenv",
                msg='check /boot/grub2/grubenv is a file rather than a link')
    else:
        test_instance.skipTest('only run in el5, el6, el8, el8+')

def test_stage1_check_hosts(test_instance):
    '''
    des: localhost ipv6 and ipv4 should be set in /etc/hosts
    '''
    expect_kws = '127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4,::1         localhost localhost.localdomain localhost6 localhost6.localdomain6'
    cmd = "sudo cat /etc/hosts"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw=expect_kws, msg='check /etc/hosts')

def test_stage1_check_hostkey_permissions(test_instance):
    '''
    bz:2013644
    check ssh files permission set are correct.
    '''
    run_cmd(test_instance,
            "ls -l /etc/ssh/{ssh_host_ecdsa_key,ssh_host_ed25519_key,ssh_host_rsa_key}",
            expect_not_kw='-rw-------. 1 root root',
            msg='check ssh files permission set are correct')

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

def test_stage1_check_ks_file_asave(test_instance):
    '''
    rhbz: n/a
    save /root/anaconda-ks.cfg for debug purpose.
    '''
    aminame = test_instance.info['name']
    ks_type = None
    if 'HA' in aminame:
        test_instance.log.info('HA AMI found')
        ks_type = 'ha'
    elif 'SAP' in aminame:
        test_instance.log.info('SAP AMI found')
        ks_type = 'sap'
    else:
        test_instance.log.info('RHEL AMI found')
        ks_type = 'vanilla'

    product_id = get_product_id(test_instance)
    if float(product_id) > float('8.4'):
        test_instance.skipTest('skip it after el8.4')
    ks_file = "{}/debug/{}_{}_{}_{}_ks.cfg".format(test_instance.logdir, test_instance.info["ami"], test_instance.info["region"], test_instance.info["release"]["arch"], ks_type)
    run_cmd(test_instance, 'sudo cp /root/anaconda-ks.cfg /tmp', expect_ret=0, msg='copy /root/anaconda-ks.cfg to /tmp')
    run_cmd(test_instance, 'sudo chmod 666 /tmp/anaconda-ks.cfg', expect_ret=0, msg='change permission')
    rmt_file = '/tmp/anaconda-ks.cfg'
    ftp_client = test_instance.ssh_client.open_sftp()
    ftp_client.get(rmt_file, ks_file)
    test_instance.log.info("ks file is saved to {}.".format(ks_file))
    ftp_client.close()

def test_stage1_check_ks_file_compare(test_instance):
    '''
    rhbz: n/a
    compare all images have same ks file content(/root/anaconda-ks.cfg).
    '''
    aminame = test_instance.info['name']
    ks_type = None
    if 'HA' in aminame:
        test_instance.log.info('HA AMI found')
        ks_type = 'ha'
    elif 'SAP' in aminame:
        test_instance.log.info('SAP AMI found')
        ks_type = 'sap'
    else:
        test_instance.log.info('RHEL AMI found')
        ks_type = 'vanilla'
    product_id = get_product_id(test_instance)
    if float(product_id) > float('8.4'):
        test_instance.skipTest('skip it after el8.4')
    src_ks_file = "{}/debug/{}_{}_{}_{}_ks.cfg".format(test_instance.logdir, test_instance.info["ami"], test_instance.info["region"], test_instance.info["release"]["arch"],ks_type)
    ks_match = "{}/debug/*{}_{}_ks.cfg".format(test_instance.logdir, test_instance.info["release"]["arch"], ks_type)
    test_instance.log.info("Try to match: {}".format(ks_match))
    dest_ks_files = glob.glob(ks_match)
    test_instance.log.info('Under {}/debug/ found {}'.format(test_instance.logdir, dest_ks_files))
    if len(dest_ks_files) == 1:
        test_instance.skipTest('skip as only one ks file found')
    if len(dest_ks_files) == 0:
        test_instance.skipTest('skip as no ks file found')
    for dest_ks_file in dest_ks_files:
        if filecmp.cmp(src_ks_file, dest_ks_file):
            test_instance.log.info('{} and {} are identical'.format(src_ks_file, dest_ks_file))
        else:
            src_text = open(src_ks_file).readlines()
            dest_text = open(dest_ks_file).readlines()
            for line in difflib.unified_diff(src_text, dest_text):
                test_instance.log.info(line)
            test_instance.fail('{} and {} have diff content, please check'.format(src_ks_file, dest_ks_file))

def test_stage1_check_instance_identity(test_instance):
    '''
    try to fetch instance identity from EC2 and compare with expectation
    '''
    aminame = test_instance.info['name']
    cmd = 'curl -s http://169.254.169.254/latest/dynamic/instance-identity/document'
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

    if 'Fedora' in aminame:
        test_instance.log.info('No need to check billingcodes in Fedora AMIs')
        return

    if 'HA' in aminame and 'Access2' not in aminame:
        # RHELDST-4222, on-demand (hourly) has the billing code for RHEL and for HA
        billingcodes = ['bp-79a54010', 'bp-6fa54006']
    elif 'Hourly2' in aminame:
        billingcodes = ['bp-6fa54006']
    elif 'Access2' in aminame:
        # Cloud Access billing code, means don't charge for the OS (so it can apply to anything cloud Access)
        billingcodes = ['bp-63a5400a']
    
    elif 'Marketplace' in aminame:
        if instance['billingProducts'] is not None:
            test_instance.fail("billingProducts is not required in marketplace image: {}".format(instance['billingProducts']))
        if instance.get('marketplaceProductCodes') is None:
            test_instance.fail("marketplaceProductCodes is required in marketplace image:{}".format(instance.get('marketplaceProductCodes')))
    else:
        test_instance.skipTest('unable to decide billingcodes as no "Hourly2" and "Access2" found in AMI name')
    if 'Marketplace' not in aminame:
        if instance.get('marketplaceProductCodes'):
            test_instance.fail('Community AMIs should not have marketplaceProductCodes')
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
    if is_fedora(test_instance):
        is_cmd_exist(test_instance, 'lshw')
        is_cmd_exist(test_instance, 'ethtool')
    cmd = 'sudo lshw -C network'
    pci_out = run_cmd(test_instance, cmd, expect_ret=0, msg='get pci devices')
    ethtool_cmd = 'sudo ethtool -i eth0'
    if 'ENA' in pci_out:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='ena', msg='check if eth0 is using ena driver')
    elif 'Virtual Function' in pci_out:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='ixgbevf', msg='check if eth0 is using ixgbevf driver')
    else:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='vif', msg='check if eth0 is using vif driver')
    cmd = 'lscpu'
    cpu_out = run_cmd(test_instance, cmd, expect_ret=0, msg='get cpu info')
    if 'Xen' not in cpu_out:
        run_cmd(test_instance, ethtool_cmd, expect_ret=0, expect_kw='ena', msg='ena must used in KVM, aarch64 and metal instances')

def test_stage1_check_network_ipv6(test_instance):
    '''
    check for networking setup
    '''
    cmd = "curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs"
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


def test_stage1_check_nm_cloud_setup(test_instance):
    '''
    rhbz: 1822853
    des: check NetworkManager-cloud-setup is installed and nm-cloud-setup is enabled
    '''
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.4'):
        test_instance.skipTest('skip it prior to el8.4')
    cmd = "rpm -q NetworkManager-cloud-setup"
    run_cmd(test_instance, cmd, expect_ret=0, msg='Check if NetworkManager-cloud-setup is installed')
    cmd = "sudo systemctl is-enabled nm-cloud-setup"
    run_cmd(test_instance, cmd, expect_ret=0, msg='Check if nm-cloud-setup is enabled')

    product_id = get_product_id(test_instance)
    #COMPOSER-842
    if float(product_id) < float('8.5'):
        file_check = '/etc/systemd/system/nm-cloud-setup.service.d/10-rh-enable-for-ec2.conf'
    else:
        file_check = '/usr/lib/systemd/system/nm-cloud-setup.service.d/10-rh-enable-for-ec2.conf'
    expect_kw='Environment=NM_CLOUD_SETUP_EC2=yes'
    cmd = "sudo cat {}".format(file_check)
    run_cmd(test_instance, cmd, expect_kw=expect_kw, msg='Check if "{}" is set in {}'.format(expect_kw, file_check))

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

def test_stage1_check_pkg_all(test_instance):
    '''
    list all installed pkgs
    '''
    cmd = "sudo rpm -qa"
    run_cmd(test_instance, cmd, expect_ret=0,timeout=120, msg='list all pkgs installed')

def test_stage1_check_pkg_signed(test_instance):
    '''
    check no pkg signature is none,
    and check that specified gpg keys are installed
    '''
    cmd = "sudo rpm -qa|grep gpg-pubkey"
    run_cmd(test_instance, cmd, expect_ret=0, msg='check gpg-pubkey installed')
    if is_fedora(test_instance):
        gpg_pubkey_num = '1'
    else:
        gpg_pubkey_num = '2'

    cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -v gpg-pubkey"
    run_cmd(test_instance, cmd, expect_ret=0, expect_not_kw='none', msg='check no pkg signature is none')
    cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -v gpg-pubkey|awk -F' ' '{print $NF}'|sort|uniq|wc -l"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw='1', msg='check use only one keyid')
    cmd = "sudo rpm -q gpg-pubkey|wc -l"
    out = run_cmd(test_instance, cmd, expect_ret=0, msg='check {} gpg-pubkey installed'.format(gpg_pubkey_num))
    if int(out) < int(gpg_pubkey_num):
        test_instance.fail("installed gpg_pubkey pkgs count {} lower than required {}".format(out, gpg_pubkey_num))

def test_stage1_check_pkg_unwanted(test_instance):
    '''
    Some pkgs are not required in ec2.
    Unwanted list:
    rhbz#1888695 rng-tools
    rhbz#2075815 qemu-guest-agent
    rhbz#2064087 dracut-config-rescue
    '''
    pkgs_unwanted = '''aic94xx-firmware,alsa-firmware,alsa-lib,alsa-tools-firmware,ivtv-firmware,iwl1000-firmware,
iwl100-firmware,iwl105-firmware,iwl135-firmware,iwl2000-firmware,iwl2030-firmware,iwl3160-firmware,
iwl3945-firmware,iwl4965-firmware,iwl5000-firmware,iwl5150-firmware,iwl6000-firmware,iwl6000g2a-firmware,
iwl6000g2b-firmware,iwl6050-firmware,iwl7260-firmware,libertas-sd8686-firmware,libertas-sd8787-firmware,
libertas-usb8388-firmware,firewalld,biosdevname,plymouth,iprutils,qemu-guest-agent,dracut-config-rescue'''.split(',')
    pkgs_unwanted = [ x.strip('\n') for x in pkgs_unwanted ]
    product_id = get_product_id(test_instance)
    if float(product_id) > float('8.3'):
        # rhbz 1888695 [rhel-8.4] Do not install rng-tools by default
        pkgs_unwanted.append('rng-tools')
    if 'SAP' in test_instance.info['name']:
        pkgs_unwanted.remove('alsa-lib')
        if float(product_id) >= float('8'):
            test_instance.log.info("libpng12 is only wanted in RHEL-7 RHELDST-10710")
            pkgs_unwanted.append('libpng12')
        if float(product_id) >= float('9'):
            test_instance.log.info("compat-sap-c++ is not wanted in RHEL-9+ RHELDST-10710")
            pkgs_unwanted.append('compat-sap-c++-9')
            pkgs_unwanted.append('compat-sap-c++-10')
            pkgs_unwanted.append('compat-sap-c++-11')
            pkgs_unwanted.append('compat-sap-c++-12')
    if 'HA' in test_instance.info['name']:
        pkgs_unwanted.append('rh-amazon-rhui-client')
    pkg_unexpected = []
    for pkg in pkgs_unwanted:
        cmd = 'rpm -q {}'.format(pkg)
        ret = run_cmd(test_instance, cmd, msg='check {} not installed'.format(pkg), ret_status=True)
        if ret == 0:
            pkg_unexpected.append(pkg)
    if pkg_unexpected:
        test_instance.fail('found unexpected pkgs: {}'.format(pkg_unexpected))

def test_stage1_check_pkg_wanted(test_instance):
    '''
    Some pkgs are required in ec2.
    https://kernel.googlesource.com/pub/scm/boot/dracut/dracut/+/18e61d3d41c8287467e2bc7178f32d188affc920%5E!/
    dracut-nohostonly -> dracut-config-generic
    dracut-norescue   -> dracut
    SAP:
    ansible-core RHELDST-10710
    '''
    pkgs_wanted = '''kernel,yum-utils,redhat-release,redhat-release-eula,cloud-init,
tar,rsync,dhcp-client,NetworkManager,NetworkManager-cloud-setup,cloud-utils-growpart,
gdisk,insights-client,dracut-config-generic,grub2-tools'''.split(',')
    pkgs_wanted = [ x.strip('\n') for x in pkgs_wanted ]
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.4'):
        pkgs_wanted.remove('NetworkManager-cloud-setup')
    if float(product_id) >= float('8.7') and float(product_id) != float('9.0'):
        #COMPOSER-1804
        pkgs_wanted.append('redhat-cloud-client-configuration')
    if float(product_id) < float('8.4') and float(product_id) >= float('8.0'):
        pkgs_wanted.append('rng-tools')
    if 'HA' in test_instance.info['name']:
        pkgs_wanted.extend(['fence-agents-all', 'pacemaker', 'pcs'])
    if 'SAP' in test_instance.info['name']:
        pkgs_wanted.extend(['rhel-system-roles-sap', 'ansible-core'])
        #BZ:1959813
        pkgs_wanted.extend(['bind-utils', 'nfs-utils', 'tcsh'])
        #BZ:1959813
        pkgs_wanted.append('uuidd')
        #BZ: 1959923, 1961168
        pkgs_wanted.extend(['cairo', 'expect', 'graphviz', 'gtk2', 'iptraf-ng', 'krb5-workstation', 'libaio'])
        pkgs_wanted.extend(['libatomic', 'libcanberra-gtk2', 'libicu', 'libpng12', 'libtool-ltdl', 'lm_sensors', 'net-tools'])
        pkgs_wanted.extend(['numactl', 'PackageKit-gtk3-module', 'xorg-x11-xauth', 'libnsl'])
        #BZ:1959962
        pkgs_wanted.append('tuned-profiles-sap-hana')
        if float(product_id) >= float('8'):
            pkgs_wanted.remove('libpng12')
        if float(product_id) < float('9'):
            pkgs_wanted.extend(['compat-sap-c++-9','compat-sap-c++-10'])
    if float(product_id) < float('8'):
        #For RHEL-7
        pkgs_wanted = '''kernel,yum-utils,cloud-init,dracut-config-generic,dracut-config-rescue,grub2,tar,rsync,chrony'''.split(',')
        pkgs_wanted = [ x.strip('\n') for x in pkgs_wanted ]
    missing_pkgs = []
    for pkg in pkgs_wanted:
        cmd = 'rpm -q {}'.format(pkg)
        ret = run_cmd(test_instance, cmd, msg='check {} installed'.format(pkg), ret_status=True)
        if ret != 0:
            missing_pkgs.append(pkg)
    if missing_pkgs:
        test_instance.fail('missing {}'.format(missing_pkgs))

def test_stage1_check_product_id(test_instance):
    '''
    bz: 1938930
    issue: RHELPLAN-60817
    check if product id matches /etc/redhat-release
    '''
    product_id = get_product_id(test_instance)
    cmd = 'sudo rpm -qa|grep redhat-release'
    run_cmd(test_instance,cmd, cancel_ret='0', msg='get redhat-release-server version')
    cmd = 'sudo rct cat-cert /etc/pki/product-default/*.pem'
    run_cmd(test_instance,cmd, expect_ret=0, expect_kw="Version: {}".format(product_id), msg='check product certificate')

def test_stage1_check_rhel_version(test_instance):
    '''
    check if rhel provider matches /etc/redhat-release and ami name
    '''
    aminame = test_instance.info['name']
    if 'Atomic' in aminame:
        test_instance.skipTest('not run in Atomic AMIs')
    if is_fedora(test_instance):
        release_file = 'fedora-release'
    else:
        release_file = 'redhat-release'
    product_id = get_product_id(test_instance)
    cmd = "sudo rpm -q --qf '%{VERSION}' --whatprovides " + release_file
    run_cmd(test_instance,cmd, expect_kw=product_id, msg='check redhat-release version match')
    if product_id not in aminame:
        test_instance.fail('{} not found in ami name: {}'.format(product_id, aminame))
    test_instance.log.info('{} found in ami name: {}'.format(product_id, aminame))

def test_stage1_check_rhui_pkg(test_instance):
    if is_fedora(test_instance):
        test_instance.skipTest('skip run in Fedora AMIs as no rhui pkg required')
    aminame = test_instance.info['name']
    unwant_rhui = None
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
        unwanted_rhui = 'rh-amazon-rhui-client-ha,rh-amazon-rhui-client-sap'
    cmd = 'sudo rpm -qa|grep rhui'
    if unwant_rhui:
        run_cmd(test_instance, cmd, expect_ret=0, expect_kw=rhui_pkg,expect_not_kw=unwanted_rhui,msg='get rhui pkg version')
    else:
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
    cmd = "sudo grep -E -q '^PasswordAuthentication yes(.*)' /etc/ssh/sshd_config"
    run_cmd(test_instance, cmd, expect_not_ret=0, msg='double check if password auth disabled')
    cmd = "sudo grep -E -q '^PasswordAuthentication no' /etc/ssh/sshd_config"
    run_cmd(test_instance, cmd, expect_ret=0, msg='double check if password auth disabled')

def test_stage1_check_sysconfig_kernel(test_instance):
    '''
    des: UPDATEDEFAULT=yes and DEFAULTKERNEL=kernel should be set in /etc/sysconfig/kernel
    '''
    expect_kws = 'UPDATEDEFAULT=yes,DEFAULTKERNEL=kernel'
    cmd = "sudo cat /etc/sysconfig/kernel"
    run_cmd(test_instance, cmd, expect_ret=0, expect_kw=expect_kws, msg='check /etc/sysconfig/kernel')

def test_stage1_check_timezone(test_instance):
    '''
    rhbz: 1187669
    check that the default timezone is set to UTC
    '''
    run_cmd(test_instance, 'date', expect_kw='UTC', msg='check timezone is set to UTC')

def test_stage1_check_udev_kernel(test_instance):
    '''
    des: /etc/udev/rules.d/80-net-name-slot.rules link to /dev/null
    ks ref:
    # For cloud images, 'eth0' _is_ the predictable device name, since
    # we don't want to be tied to specific virtual (!) hardware
    rm -f /etc/udev/rules.d/70*
    ln -s /dev/null /etc/udev/rules.d/80-net-name-slot.rules
    '''
    product_id = get_product_id(test_instance)
    if float(product_id) > float('8.4'):
        #COMPOSER-844 - this set not required in rhel8+
        cmd = "sudo ls -l /etc/udev/rules.d/80-net-name-slot.rules"
        run_cmd(test_instance, cmd, expect_not_ret=0, msg='check /etc/udev/rules.d/80-net-name-slot.rules not existing')
    else:
        expect_kws = '/dev/null'
        cmd = "sudo ls -l /etc/udev/rules.d/80-net-name-slot.rules"
        run_cmd(test_instance, cmd, expect_ret=0, expect_kw=expect_kws, msg='check /etc/udev/rules.d/80-net-name-slot.rules')
    cmd = 'sudo cat /etc/udev/rules.d/70-persistent-net.rules'
    run_cmd(test_instance, cmd, expect_ret=0,msg='check /etc/udev/rules.d/70-persistent-net.rules')

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
    if is_fedora(test_instance):
        test_instance.skipTest('skip run in Fedora AMIs')
    product_id = get_product_id(test_instance)
    if float(product_id) < float('8.4'):
        expect_kw="enabled=0"
        status = 'disabled'
    else:
        expect_kw="enabled=1"
        status = 'enabled'
    cmd = 'sudo cat /etc/yum/pluginconf.d/product-id.conf'
    run_cmd(test_instance,cmd, expect_ret=0, expect_kw=expect_kw, msg='check yum product-id plugin is {}'.format(status))
    cmd = 'sudo cat /etc/yum/pluginconf.d/subscription-manager.conf'
    run_cmd(test_instance,cmd, expect_ret=0, expect_kw=expect_kw, msg='check yum subscription-manager plugin is {}'.format(status))