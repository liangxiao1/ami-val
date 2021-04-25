import os, shutil
import random
import re
import time
import string
import logging
import decimal
import subprocess
import tipset
import json
import difflib
import urllib.request as request
import time
import importlib
import copy
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from filelock import FileLock
from . import aws_lib
from tipset.libs import minilog,rmt_ssh
from functools import wraps
from . import resource_class
from jinja2 import Template, FileSystemLoader, Environment, PackageLoader, select_autoescape

def wait_for(ret=None, not_ret=None, ck_ret=False, ck_not_ret=False, timeout=60, interval=1, log=None):
    '''
    wait for a func return expected value within specified time
    '''
    if log == None:
        log = minilog.minilog()
    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            while True:
                log.info("{} called, timeout {}".format(func.__name__, timeout))
                result = func(*args, **kwargs)
                if ck_ret and result == ret:
                    break
                if ck_not_ret and not_ret != result:
                    break
                end_time = time.time()
                time.sleep(interval)
                if end_time - start_time > timeout:
                    log.info('timeout, exit!')
                    break
            return result
        return wrapper
    return decorate

def write_sumlog(logfile, ami_id='', ami_name='', region='', casename='', result='', error=''):
    if not os.path.exists(logfile):
        with FileLock(logfile + '.lock'):
            with open(logfile, 'w+') as fh:
                x={}
                x['ami'] = ami_id
                x['result'] = [{"casename":casename, "result":result, "error":error}]
                x['region'] = region
                x['name'] = ami_name
                sums = [x]
                json.dump(sums, fh, indent=4)
        return True
    with FileLock(logfile + '.lock'):
        with open(logfile, 'r') as fh:
            sums = json.load(fh)
            is_found = False
            for ami in sums:
                if ami_id == ami['ami']:
                    is_found = True
                    break
            if is_found:
                for ami in sums:
                    if ami_id == ami['ami']:
                        ami['result'].append({"casename":casename, "result":result, "error":error})
                        break
            else:
                x={}
                x['ami'] = ami_id
                x['result'] = [{"casename":casename, "result":result, "error":error}]
                x['region'] = region
                x['name'] = ami_name
                sums.append(x)
        with open(logfile, 'w+') as fh:
            json.dump(sums, fh, indent=4)

def save_resource(logfile, ami_id=None, region=None, arch=None, instance_types_list=None, instance_type=None, instance_id=None, instance_hostname=None, subnet=None, sg=None, log=None):
    '''
    ami_id, region, arch is query condition and readonly when saving data to resource file.
    '''
    if log is None:
        log = minilog.minilog()
    if ami_id is None and region is None:
        log.info("Please specify ami_id or region to update resource file:{}".format(logfile))
        return True
    log.info("update resource file:{}".format(logfile))
    with FileLock(logfile + '.lock'):
        with open(logfile, 'r') as fh:
            sums = json.load(fh)
            is_found = False
            for ami in sums:
                #log.info("checking {} {} {}".format(ami['ami'], ami['region'], region))
                if ami_id is not None and ami_id == ami['ami']:
                    is_found = True
                    break
                if region is not None and region in ami['region']:
                    is_found = True
                    break
            if is_found:
                if ami_id is not None:
                    log.info("update ami info {}".format(ami_id))
                    for ami in sums:
                        if ami_id == ami['ami']:
                            if instance_type is not None:
                                ami['instance_type'] = instance_type
                            if instance_types_list is not None:
                                ami['instance_types_list'] = instance_types_list
                            if instance_id is not None:
                                ami['instance_id'] = instance_id
                            if instance_hostname is not None:
                                ami['instance_hostname'] = instance_hostname
                            if subnet is not None:
                                ami['subnet'] = subnet
                            if sg is not None:
                                ami['sg'] = sg
                if region is not None and arch is None:
                    log.info("update region info {}".format(region))
                    for ami in sums:
                        if region in ami['region']:
                            if instance_type is not None:
                                ami['instance_type'] = instance_type
                            if instance_types_list is not None:
                                ami['instance_types_list'] = instance_types_list
                            if instance_id is not None:
                                ami['instance_id'] = instance_id
                            if instance_hostname is not None:
                                ami['instance_hostname'] = instance_hostname
                            if subnet is not None:
                                ami['subnet'] = subnet
                            if sg is not None:
                                ami['sg'] = sg
                if region is not None and arch is not None:
                    log.info("update region info {} which arch {} matched".format(region, arch))
                    for ami in sums:
                        if region in ami['region'] and arch in ami['release']['arch']:
                            if instance_type is not None:
                                ami['instance_type'] = instance_type
                            if instance_types_list is not None:
                                ami['instance_types_list'] = instance_types_list
                            if instance_id is not None:
                                ami['instance_id'] = instance_id
                            if instance_hostname is not None:
                                ami['instance_hostname'] = instance_hostname
                            if subnet is not None:
                                ami['subnet'] = subnet
                            if sg is not None:
                                ami['sg'] = sg
        with open(logfile, 'w+') as fh:
            json.dump(sums, fh, indent=4)
        log.info("updated resource file:{}".format(logfile))
    return True

def write_html(sumlog, region_missed=None, region_uploaded=None):
    """
    sumlog: result log
    region_missed: which region does not have this AMI
    region_uploaded: which region has this AMI
    """
    logfile = sumlog
    logdir = os.path.dirname(logfile)
    sumlog_html = logdir + '/sum.html'
    result_tmp = resource_class.Result()

    with open(logfile, 'r') as fh:
        sums = json.load(fh)
        for ami in sums:
            ami_id = ami['ami']
            region = ami['region']
            name = ami['name']
            for r in ami['result']:
                result = r['result']
                if 'PASS' in result:
                    result_tmp.case_pass += 1
                elif 'FAIL' in result:
                    result_tmp.case_fail += 1
                elif 'SKIP' in result:
                    result_tmp.case_skip += 1
                elif 'ERROR' in result:
                    result_tmp.case_error += 1
                else:
                    result_tmp.case_fail += 1
    with open(logfile, 'r') as fh:
        sums = json.load(fh)
        for ami in sums:
            ami_id = ami['ami']
            region = ami['region']
            name = ami['name']
            for r in ami['result']:
                casename = r['casename']
                result = r['result']
                error = r['error']
                debuglog = 'debug/' + ami_id + '_' + casename + '.log'
                result_tmp.cases.append((ami_id, region, name, casename, result, error, debuglog))
    file_loader = PackageLoader('ami_val','templates')
    env = Environment(loader=file_loader)
    template = env.get_template('sum.html')
    output = template.render(result=result_tmp, region_missed=region_missed, region_uploaded=region_uploaded)
    with open(sumlog_html, 'w+') as fh:
        print(output, file=fh)
    print("HTML summary:{}".format(sumlog_html))
            

def prepare_dir(args):
    logdir = args.logdir
    if 'http' in args.amis_file:
        print("Task url provided, try to download it")
        task_url = args.amis_file.replace('push','task')
        task_url = task_url.replace('https','http')
        json_url = task_url + "/log/images.json?format=raw"
        print('Get data from %s' % json_url)
        s = request.urlopen(json_url)
        print('Got data from %s' % s.geturl())
        task_id = task_url.rstrip('/').split('/')[-1]
        logdir = "{}_{}".format(logdir, task_id)
        if os.path.exists(logdir):
            print("Remove exists {}".format(logdir))
            shutil.rmtree(logdir)
        if not os.path.exists(logdir):
            print("Create new {}".format(logdir))
            os.mkdir(logdir)
        amis_file = '{}/images.json'.format(logdir)
        if os.path.exists(amis_file):
            os.unlink(amis_file)
            print('Removed exists %s' % amis_file)
        with open(amis_file, 'b+w') as fh:
            fh.write(s.read())
        print('Data saved to %s' % amis_file)
    elif os.path.exists(args.amis_file):
        amis_file = '{}/images.json'.format(logdir)
        if os.path.exists(logdir):
            print("Remove exists {}".format(logdir))
            shutil.rmtree(logdir)
        if not os.path.exists(logdir):
            print("Create new {}".format(logdir))
            os.mkdir(logdir)
        shutil.copy(args.amis_file, amis_file )
    os.mkdir(logdir + "/debug")
    return logdir, amis_file

def tests_discover(args):
    this_dir = os.path.dirname(__file__)
    this_dir = os.path.dirname(this_dir)
    ts = ["ami_val.tests." + x for x in os.listdir(this_dir + '/tests') if x.startswith('test')]
    ts = [x[:-3] for x in ts]
    all_cases = []
    for stage in ts:
        # print("Run {} test".format(stage))
        #s = importlib.import_module(stage, __package__)
        s = importlib.import_module(stage)
        for case in dir(s):
            if case.startswith('test'):
                all_cases.append("{}.{}".format(s.__name__, case))
    #print("all cases{}".format(all_cases))
    if args.pattern is not None:
        print("case in stage0 is must required!")
        tmp_cases_list = []
        for case in all_cases:
            for p in args.pattern.split(','):
                if p in case or 'stage0' in case and case not in tmp_cases_list:
                    tmp_cases_list.append(case)
            if args.skip_pattern is not None and 'stage0' not in case:
                for p in args.skip_pattern.split(','):
                    if p in case and 'stage0' not in case:
                        if case in tmp_cases_list:
                            tmp_cases_list.remove(case)
    if args.pattern is None and args.skip_pattern is not None:
        print("case in stage0 is must required!")
        tmp_cases_list = copy.deepcopy(all_cases)
        for case in all_cases:
            if 'stage0' not in case:
                for p in args.skip_pattern.split(','):
                    if p in case and 'stage0' not in case:
                        if case in tmp_cases_list:
                            tmp_cases_list.remove(case)
    if args.pattern is not None or args.skip_pattern is not None:
        final_ts = tmp_cases_list
    else:
        final_ts = all_cases
    final_ts.sort()
    return final_ts


def msg_to_syslog(test_instance, msg=None):
    '''
    Save msg to journal log and dmesg.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        msg {string} -- msg want to save, default is casename
    Return:
        arm: return True
        other: return False
    '''
    if msg is None:
        msg = test_instance.id()
    cmd = "sudo echo os-tests:{} | systemd-cat -p info".format(msg)
    run_cmd(test_instance, cmd, expect_ret=0)
    cmd = "sudo bash -c 'echo \"{}\" > /dev/kmsg'".format(msg)
    run_cmd(test_instance, cmd, expect_ret=0)

def run_cmd(test_instance,
            cmd,
            expect_ret=None,
            expect_not_ret=None,
            expect_kw=None,
            expect_not_kw=None,
            expect_output=None,
            msg=None,
            cancel_kw=None,
            cancel_not_kw=None,
            cancel_ret=None,
            cancel_not_ret=None,
            timeout=60,
            ret_status=False,
            is_log_output=True,
            is_log_cmd=True,
            cursor=None,
            rmt_redirect_stdout=False,
            rmt_redirect_stderr=False,
            rmt_get_pty=False
            ):
    """run cmd with/without check return status/keywords and save log

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        cmd {string} -- cmd to run
        expect_ret {int} -- expected return status
        expect_not_ret {int} -- unexpected return status
        expect_kw {string} -- string expected in output,seperate by ',' if
                              check multi words
        expect_not_kw {string} -- string not expected in output, seperate by
                                  ',' if check multi words
        expect_output {string} -- string exactly the same as output
        cancel_kw {string} -- cancel case if kw not found, seperate by ','
                              if check multi words
        cancel_not_kw {string} -- cancel case if kw found, seperate by ','
                              if check multi words
        cancel_ret {string} -- cancel case if ret code not match, seperate by ','
                              if check multi rets
        cancel_not_ret {string} -- cancel case if ret code found, seperate by ','
                              if check multi rets
        msg {string} -- addtional info to mark cmd run.
        ret_status {bool} -- return ret code instead of output
        is_log_output {bool} -- print cmd output or not
        is_log_cmd {bool} -- log cmd in plain text
        cursor {string} -- skip content before cursor(line)
        rmt_redirect_stdout {bool} -- ssh command not exit some times, redirect stdout to tmpfile if needed
        rmt_redirect_stderr {bool} -- ssh command not exit some times, redirect stderr to tmpfile if needed

    Keyword Arguments:
        check_ret {bool} -- [whether check return] (default: {False})
    """
    if msg is not None:
        test_instance.log.info(msg)
    if is_log_cmd:
        test_instance.log.info("CMD: {}".format(cmd))
    status = None
    output = None
    exception_hit = False

    try:
        if test_instance.ssh_client is not None:
            status, output = rmt_ssh.remote_excute(test_instance.ssh_client, cmd, timeout, redirect_stdout=rmt_redirect_stdout, redirect_stderr=rmt_redirect_stderr,rmt_get_pty=rmt_get_pty, log=test_instance.log)
        else:
            ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
            status = ret.returncode
            if ret.stdout is not None:
                output = ret.stdout
    except Exception as err:
        test_instance.log.error("Run cmd failed as {}".format(err))
        test_instance.log.info("Try to start a new connection")
        test_instance.ssh_client = test_instance.vm.new_ssh_client()
        status = None
        exception_hit = True

    if exception_hit:
        test_instance.log.info("Try again")
        test_instance.log.info("Test via uname, if still fail, please make sure no hang or panic in sys")
        try:
            if test_instance.ssh_client is not None:
                status, output = rmt_ssh.remote_excute(test_instance.ssh_client, 'uname -a', timeout, log=test_instance.log)
                status, output = rmt_ssh.remote_excute(test_instance.ssh_client, cmd, timeout, redirect_stdout=rmt_redirect_stdout, redirect_stderr=rmt_redirect_stderr, rmt_get_pty=rmt_get_pty, log=test_instance.log)
            else:
                ret = subprocess.run('uname -a', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
                status = ret.returncode
                if ret.stdout is not None:
                   output = ret.stdout
                test_instance.log.info("Return: {}".format(output.decode("utf-8")))
                ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
                status = ret.returncode
                if ret.stdout is not None:
                   output = ret.stdout
        except Exception as err:
            test_instance.log.error("Run cmd failed again {}".format(err))
    if cursor is not None and cursor in output:
        output = output[output.index(cursor):]
    if is_log_output:
        test_instance.log.info("CMD ret: {} out:{}".format(status, output))
    else:
        test_instance.log.info("CMD ret: {}".format(status))
    if expect_ret is not None:
         if status != expect_ret:
            test_instance.fail('ret is {}, expected ret is {}'.format(status, expect_ret))
    if expect_not_ret is not None:
        if status == expect_not_ret:
            test_instance.fail('ret is {}, expected not ret is {}'.format(status, expect_not_ret))
    if expect_kw is not None:
        for key_word in expect_kw.split(','):
            if output.count('\n') > 5:
                find_list = re.findall('.*{}.*\n'.format(re.escape(key_word)), output)
            else:
                find_list = re.findall('.*{}.*'.format(re.escape(key_word)), output)
            if len(find_list) > 0:
                test_instance.log.info('expcted "{}" found in "{}"'.format(key_word, ''.join(find_list)))
            else:
                if output.count('\n') > 5:
                    test_instance.fail('expcted "{}" not found in output(check debug log as too many lines)'.format(key_word))
                else:
                    test_instance.fail('expcted "{}" not found in "{}"'.format(key_word,output))
    if expect_not_kw is not None:
        for key_word in expect_not_kw.split(','):
            if output.count('\n') > 5:
                find_list = re.findall('.*{}.*\n'.format(re.escape(key_word)), output)
            else:
                find_list = re.findall('.*{}.*'.format(re.escape(key_word)), output)
            if len(find_list) == 0:
                test_instance.log.info('Unexpcted "{}" not found in output'.format(key_word))
            else:
                if output.count('\n') > 5:
                    test_instance.fail('Unexpcted "{}" found in {}'.format(key_word, ''.join(find_list)))
                else:
                    test_instance.fail('Unexpcted "{}" found in "{}"'.format(key_word,output))
    if expect_output is not None:
        if expect_output != output:
            test_instance.fail('exactly expected {}, but actual output is {}'.format(expect_output, output))

    if cancel_kw is not None:
        cancel_yes = True
        for key_word in cancel_kw.split(','):
            if key_word in output:
                cancel_yes = False
        if cancel_yes:
            test_instance.skipTest("'{}' not found, skip case. msg:{}".format(cancel_kw, msg))
    if cancel_not_kw is not None:
        for key_word in cancel_not_kw.split(','):
            if key_word in output:
                test_instance.skipTest("'{}' found, skip case. msg:{}".format(key_word, msg))
    if cancel_ret is not None:
        cancel_yes = True
        for ret in cancel_ret.split(','):
            if int(ret) == int(status):
                cancel_yes = False
        if cancel_yes:
            test_instance.skipTest("expected ret code '{}' not match ret '{}', cancel case. msg:{}".format(cancel_ret, status, msg))
    if cancel_not_ret is not None:
        for ret in cancel_not_ret.split(','):
            if int(ret) == int(status):
                test_instance.skipTest("skip ret code '{}' found, actual ret '{}' cancel case. msg:{}".format(ret, status, msg))
    if ret_status:
        return status
    return output

def compare_nums(test_instance, num1=None, num2=None, ratio=0, msg='Compare 2 nums'):
    '''
    Compare num1 and num2.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        num1 {int} -- num1
        num2 {int} -- num2
        ratio {int} -- allow ratio
    Return:
        num1 < num2: return True
        (num1 - num2)/num2*100 > ratio: return False
        (num1 - num2)/num2*100 < ratio: return True
    '''
    num1 = float(num1)
    num2 = float(num2)
    ratio = float(ratio)
    test_instance.log.info(msg)
    if num1 < num2:
        test_instance.log.info("{} less than {}".format(num1, num2))
        return True
    if (num1 - num2)/num2*100 > ratio:
        test_instance.fail("{} vs {} over {}%".format(num1, num2, ratio))
    else:
        test_instance.log.info("{} vs {} less {}%, pass".format(num1, num2, ratio))

def getboottime(test_instance):
    '''
    Get system boot time via "systemd-analyze"
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    '''
    run_cmd(test_instance, "sudo which systemd-analyze", expect_ret=0)
    time_start = int(time.time())
    while True:
        output = run_cmd(test_instance, "sudo systemd-analyze")
        if 'Bootup is not yet finished' not in output:
            break
        time_end = int(time.time())
        run_cmd(test_instance, 'sudo systemctl list-jobs')
        if time_end - time_start > 60:
            test_instance.fail("Bootup is not yet finished after 60s")
        test_instance.log.info("Wait for bootup finish......")
        time.sleep(1)
    cmd = "sudo systemd-analyze blame > /tmp/blame.log"
    run_cmd(test_instance, cmd, expect_ret=0)
    run_cmd(test_instance, "cat /tmp/blame.log", expect_ret=0)
    output = run_cmd(test_instance, "sudo systemd-analyze", expect_ret=0)
    boot_time = re.findall("=.*s", output)[0]
    boot_time = boot_time.strip("=\n")
    boot_time_sec = re.findall('[0-9.]+s', boot_time)[0]
    boot_time_sec = boot_time_sec.strip('= s')
    if 'min' in boot_time:
        boot_time_min = re.findall('[0-9]+min', boot_time)[0]
        boot_time_min = boot_time_min.strip('min')
        boot_time_sec = int(boot_time_min) * 60 + decimal.Decimal(boot_time_sec).to_integral()
    test_instance.log.info(
        "Boot time is {}(s)".format(boot_time_sec))
    return boot_time_sec

def is_arch(test_instance, arch="", action=None):
    '''
    Check whether system is specific system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        arch {string} -- arch want to check
        action {string} -- cancel case if it is not arch
    Return:
        arm: return True
        other: return False
    '''
    output = run_cmd(test_instance, "lscpu", expect_ret=0)
    if arch in output:
        test_instance.log.info("{} detected.".format(arch))
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non {} platform.".format(arch))
    test_instance.log.info("Not an {} instance.".format(arch))
    return False

def is_aws(test_instance, action=None):
    '''
    Check whether system is a aws system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a aws system
    Return:
        aws: return True
        other: return False
    '''
    output = run_cmd(test_instance, "cat /sys/devices/virtual/dmi/id/bios_*", expect_ret=0)
    if 'amazon' in output.lower():
        test_instance.log.info("AWS system.")
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non aws system.")
        test_instance.log.info("Not an aws system.")
    return False

def is_metal(test_instance, action=None):
    '''
    Check whether system is a baremetal system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a bare metal system
    Return:
        metal: return True
        other: return False
    '''
    output_lscpu = run_cmd(test_instance, "lscpu", expect_ret=0)
    if "x86_64" in output_lscpu and "Hypervisor" not in output_lscpu:
        test_instance.log.info("It is a bare metal instance.")
        return True
    elif "x86_64" in output_lscpu and "Hypervisor" in output_lscpu:
        test_instance.log.info("It is a virtual guest.")
        if action == "cancel":
            test_instance.skipTest("Cancel it in non metal system.")
        return False
    output_dmesg = run_cmd(test_instance, "dmesg", expect_ret=0, is_log_output=False)

    if 'HYP mode not available' in output_dmesg:
        test_instance.log.info("It is a virtual guest.")
        if action == "cancel":
            test_instance.skipTest("Cancel it in non metal system.")
        return False
    else:
        test_instance.log.info("It is a bare metal instance.")
        return True

def is_cmd_exist(test_instance, cmd=None, is_install=True, cancel_case=False):
    '''
    check cmd exists status, if no, try to install it.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        cmd {string} -- checked command
        is_install {bool} -- try to install it or not
    '''
    cmd_check = "which %s" % cmd
    ret = run_cmd(test_instance, cmd_check, ret_status=True)
    if ret == 0:
        return True
    else:
        test_instance.log.info("No %s found!" % cmd)
    if not is_install:
        if cancel_case:
            test_instance.skipTest("Cancel it as {} not found".format(cmd))
        return False
    arch = run_cmd(test_instance, 'uname -p').rstrip('\n')
    pkg_find = "sudo yum provides %s" % cmd
    output = run_cmd(test_instance, pkg_find, expect_ret=0)
    for i in [arch, 'noarch']:
        pkg_list = re.findall("[^\s]+%s" % i, output)
        if len(pkg_list) > 0:
            break
    if len(pkg_list) == 0:
        test_instance.skipTest("Unable to install {}".format(cmd))
        return False
    run_cmd(test_instance, "sudo yum install -y %s" % pkg_list[0], expect_ret=0, timeout=120)
    return True

def is_pkg_installed(test_instance, pkg_name=None, is_install=True, cancel_case=False):
    '''
    check cmd exists status, if no, try to install it.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        cmd {string} -- checked command
        is_install {bool} -- try to install it or not
    '''
    cmd_check = "rpm -qa|grep {}".format(pkg_name)
    ret = run_cmd(test_instance, cmd_check, ret_status=True)
    if ret == 0:
        return True
    else:
        test_instance.log.info("No %s found!" % pkg_name)
        return False

def pkg_install(test_instance, pkg_name=None, pkg_url=None):
        """
        Install pkg in target system from default repo or pkg_url.
        $pkg_url_$arch is defined in configuration file.
        I use pre compiled pkgs for saving time in run.
        eg.
        blktests_url_x86_64: https://github.com/liangxiao1/rpmbuild_specs/releases/download/blktests_20201009/blktests-master-20201009.aarch64.rpm
        or
        blktests_url_aarch64: https://github.com/liangxiao1/rpmbuild_specs/releases/download/blktests_20201009/blktests-master-20201009.aarch64.rpm
        Arguments:
            test_instance {avocado Test instance} -- avocado test instance
            pkg_name {string} -- pkg name
            pkg_url {string} -- pkg url if it is not in default repo
        """

        if not is_pkg_installed(test_instance, pkg_name=pkg_name):
            test_instance.log.info("Try install {} automatically!".format(pkg_name))
            if pkg_url is not None:
                test_instance.log.info("Install {} from {}".format(pkg_name, pkg_url))
                cmd = 'sudo yum -y install %s' % pkg_url
            else:
                test_instance.log.info("Install {} from default repo".format(pkg_name))
                cmd = 'sudo yum -y install %s' % pkg_name
            run_cmd(test_instance, cmd, timeout=1200)
        elif test_instance.params.get('pkg_reinstall'):
            test_instance.log.info("Try reinstall {} automatically!".format(pkg_name))
            if pkg_url is not None:
                test_instance.log.info("Reinstall {} from {}".format(pkg_name, pkg_url))
                cmd = 'sudo yum -y reinstall %s' % pkg_url
            else:
                test_instance.log.info("Reinstall {} from default repo".format(pkg_name))
                cmd = 'sudo yum -y reinstall %s' % pkg_name
            run_cmd(test_instance, cmd, timeout=1200)

        if not is_pkg_installed(test_instance, pkg_name=pkg_name) and pkg_url is not None:
            test_instance.log.info('Install without dependences!')
            cmd = 'sudo rpm -ivh %s --nodeps' % pkg_url
            run_cmd(test_instance, cmd, timeout=1200)
        if not is_pkg_installed(test_instance, pkg_name=pkg_name):
            test_instance.skipTest("Cannot install {} automatically!".format(pkg_name))

def get_memsize(test_instance, action=None):
    '''
    Check whether system is a aws system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a aws system
    Return:
        aws: return True
        other: return False
    '''
    output = run_cmd(test_instance, "cat /proc/meminfo |grep MemTotal", expect_ret=0)

    mem_kb = int(re.findall('\d+', output)[0])
    mem_gb = (mem_kb/1024/1024)
    test_instance.log.info("Total memory: {:0,.1f}GiB".format(mem_gb))
    return mem_gb

def get_cmd_cursor(test_instance, cmd='dmesg -T', rmt_redirect_stdout=False, rmt_get_pty=False):
    '''
    Get command cursor by last matched line.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    Return:
        cursor {string}
    '''
    output = run_cmd(test_instance, cmd, expect_ret=0, is_log_output=False, rmt_redirect_stdout=rmt_redirect_stdout, rmt_get_pty=rmt_get_pty)
    if len(output.split('\n')) < 5:
        return output.split('\n')[-1]
    for i in range(-1, -10, -1):
        cursor = output.split('\n')[i]
        if len(cursor) > 3:
            break
    test_instance.log.info("Get cursor: {}".format(cursor))
    return cursor

def check_log(test_instance, log_keyword, log_cmd="journalctl --since today", match_word_exact=False, cursor=None, skip_words=None, rmt_redirect_stdout=False, rmt_redirect_stderr=False, rmt_get_pty=False):
    '''
    check journal log
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        log_keyword: which keywords to check, eg error, warn, fail, default is checking journal log happened in today.
        log_cmd: the command to get log
        match_word_exact: is macthing word exactly
        cursor: where to start to check journal log, only for journal log
        skip_words: skip words as you want, split by ","
    '''
    # Baseline data file
    baseline_file = os.path.dirname(os_tests.__file__) + "/data/baseline_log.json"
    # Result dir
    with open(baseline_file,'r') as fh:
        test_instance.log.info("Loading baseline data file from {}".format(baseline_file))
        baseline_dict = json.load(fh)
    run_cmd(test_instance, '\n')
    check_cmd = log_cmd

    if match_word_exact:
        check_cmd = check_cmd + '|grep -iw %s' % log_keyword
    ret = False
    if cursor is not None:
        out = run_cmd(test_instance,
                      check_cmd,
                      expect_ret=0,
                      msg='Get log......', cursor=cursor,
                      rmt_redirect_stderr=rmt_redirect_stderr,
                      rmt_redirect_stdout=rmt_redirect_stdout,
                      rmt_get_pty=rmt_get_pty)
    else:
        out = run_cmd(test_instance,
                      check_cmd,
                      expect_ret=0,
                      msg='Get log......',
                      rmt_redirect_stderr=rmt_redirect_stderr,
                      rmt_redirect_stdout=rmt_redirect_stdout,
                      rmt_get_pty=rmt_get_pty)

    for keyword in log_keyword.split(','):
        ret = find_word(test_instance, out, keyword, baseline_dict=baseline_dict, skip_words=skip_words)
        if not ret and baseline_dict is not None:
            test_instance.fail("New {} in {} log".format(keyword, check_cmd))
        elif not ret:
            test_instance.fail("Found {} in {} log!".format(keyword, check_cmd))
        else:
            test_instance.log.info("No unexpected {} in {} log!".format(keyword, check_cmd))

def clean_sentence(test_instance, line1, line2):
    """only keep neccessary words
    eg.
    line1: Sep 10 05:42:38 ip-172-31-1-196.us-west-2.compute.internal augenrules[783]: failure 1
    line2: augenrules[681]: failure 1

    return:
    line1: augenrules[681]: failure 1
    line2: augenrules[783]: failure 1

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        line1 {string} -- string 1
        line2 {string} -- string 2
    Returns:
        line1
        line2
    """
    tmpline = ''
    line1_longer = True
    if len(line1) > len(line2):
        tmpline = line2
    else:
        tmpline = line1
        line1_longer = False
    for i in re.findall("\w+",tmpline):
        if len(i) >= 3:
            if i not in line1 or i not in line2:
                return line1, line2
            #test_instance.log.info("got start word {}".format(i))
            if line1_longer:
                line1 = line1[line1.index(i):]
            else:
                line2 = line2[line2.index(i):]
            #test_instance.log.info("return line1:{} line2:{}".format(line1, line2))
            return line1, line2
    return line1, line2

def find_word(test_instance, check_str, log_keyword, baseline_dict=None, skip_words=None):
    """find words in content

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        check_str {[string]} -- [string to look]
        baseline_dict {[dict]} -- [baseline dict to compare]
        match_word_exact: is macthing word exactly
        skip_words: skip words as you want, split by ","

    Returns:
        [Bool] -- [True|False]
    """
    tmp_list = re.findall('.*%s.*\n' % log_keyword, check_str, flags=re.I)
    if len(tmp_list) == 0:
        test_instance.log.info("No %s found!", log_keyword)
        return True
    else:
        test_instance.log.info("%s found!", log_keyword)
    if skip_words is not None:
        for skip_word in skip_words.split(','):
            tmp_list = [x for x in tmp_list if skip_word not in x]
    if len(tmp_list) == 0:
        test_instance.log.info("No {} found after skipped {}!".format(log_keyword, skip_words))
        return True
    # compare 2 string, if similary over fail_rate, consider it as same.
    fail_rate = 70
    no_fail = True
    for line1 in tmp_list:
        find_it = False
        if baseline_dict is not None:
            for basekey in baseline_dict:
                line1_tmp = line1
                line2_tmp = baseline_dict[basekey]["content"]
                line1_tmp, line2_tmp = clean_sentence(test_instance, line1_tmp, line2_tmp)
                seq = difflib.SequenceMatcher(
                    None, a=line1_tmp, b=line2_tmp)
                same_rate = seq.ratio() * 100
                if same_rate > fail_rate:
                    test_instance.log.info(
                        "Compare result rate: %d same, maybe it is not a \
new one", same_rate)
                    test_instance.log.info("Guest: %s Baseline: %s", line1,
                             baseline_dict[basekey]["content"])
                    test_instance.log.info("ID:%s Baseline analyze:%s Branch:%s Status:%s Link:%s Path:%s" %
                             (basekey,
                              baseline_dict[basekey]["analyze"],
                              baseline_dict[basekey]["branch"],
                              baseline_dict[basekey]["status"],
                              baseline_dict[basekey]["link"],
                              baseline_dict[basekey]["path"]))
                    if baseline_dict[basekey]["trigger"] in check_str and len(baseline_dict[basekey]["trigger"]) > 2:
                        test_instance.log.info("Maybe it is expected because found '{}' too".format(baseline_dict[basekey]["trigger"]))
                        find_it = True
                    if baseline_dict[basekey]["status"] == 'active':
                        find_it = True
                    else:
                        test_instance.log.info("Find a similar issue which should be already fixed, please check manually.")
                        find_it = False
                        no_fail = False
                    break
        if not find_it:
            test_instance.log.info("This is a new exception!")
            test_instance.log.info("{}".format(line1))
            no_fail = False

    return no_fail

def get_product_id(test_instance):
    check_cmd = "sudo cat /etc/redhat-release"
    output = run_cmd(test_instance,check_cmd, expect_ret=0, msg='check release name')
    product_id = re.findall('[\d.]{2,3}', output)[0]
    test_instance.log.info("Get product id: {}".format(product_id))
    return product_id

def is_fedora(test_instance):
    aminame = test_instance.info['name']
    if 'Fedora' in aminame:
        test_instance.log.info('Fedora AMI found from name:{}'.format(aminame))
    else:
        return False
    if test_instance.vm is not None:
        check_cmd = "sudo cat /etc/redhat-release"
        output = run_cmd(test_instance,check_cmd, expect_ret=0, msg='check release name')
        if 'Fedora' in output:
            test_instance.log.info('Fedora system found inside AMI {}'.format(aminame))
        else:
            return False
    return True
