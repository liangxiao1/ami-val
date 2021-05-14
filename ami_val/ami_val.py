import argparse
import copy
import os
import shutil
import sys
from ami_val import tests
from ami_val.libs import utils_lib, resource_class, aws_lib
from ami_val.libs.resource_class import FailException, SkipException
import ami_val
import json
import concurrent.futures
import signal
import traceback

ALL_TS = []

def sig_handler(signum, frame):
    print('Got signal {}, call cleanup and exit!'.format(signum))
    cleanup_paralle(ALL_TS)
    sys.exit(0)

def cleanup_paralle(ts_list):
    #Sending SIGTERM (CTRL+c, KeyboardInterrupt) while Python is waiting in threading.Thread.join() is not supported.
    # so set the timeout to 60
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        all_jobs = {executor.submit(cleanup_single, ts): ts for ts in ts_list}
        for r in concurrent.futures.as_completed(all_jobs, timeout=60):
            x = all_jobs[r]
            try:
                data = r.result()
            except Exception as exc:
                print("{} generated an exception: {}".format(r,exc))
            else:
                pass

def cleanup_single(ts):
    try:
        if ts.vm is not None:
            ts.vm.delete(wait=False)
    except Exception as error:
        pass

def init_ts_vm(ts, instance_id=None):
    vm = resource_class.EC2VM(ts)
    if instance_id is None and vm.create():
        ts.vm = vm
        ts.ssh_client = vm.new_ssh_client()
    else:
        if vm.reuse_init(instance_id):
            ts.vm = vm
        #ts.ssh_client = vm.new_ssh_client()
    return ts

def main():
    parser = argparse.ArgumentParser(
    description="ami-val is a lightweight, fast check and tests collection for AMIs.")
    parser.add_argument('-l', dest='is_listcase', action='store_true',
                    help='list supported cases without run', required=False)
    parser.add_argument('-p', dest='pattern', default=None, action='store',
                    help='filter case by name', required=False)
    parser.add_argument('-s', dest='skip_pattern', default=None, action='store',
                    help='skip cases', required=False)
    parser.add_argument('-f', dest='amis_file', default=None, action='store',
                    help='Amis json file or the task url', required=False)
    parser.add_argument('--logdir', dest='logdir', default='/tmp/ami_val', action='store',
                    help='specify logdir, default is /tmp/ami_val if only amis json file specified', required=False)
    parser.add_argument('--clean', dest='is_clean', action='store_true', default=False,
                    help='release resource created in logdir specified', required=False)
    parser.add_argument('--profile', dest='profile', default='default', action='store',
                    help='aws credential profile name, default is default', required=False)
    parser.add_argument('--paralle', dest='is_paralle', action='store_true', default=False,
                    help='run tests in all regions in paralle', required=False)
    args = parser.parse_args()

    signal.signal(signal.SIGHUP, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGQUIT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    print("Run in mode: is_listcase:{} pattern:{} is_paralle:{}".format(args.is_listcase, args.pattern, args.is_paralle))
    found_cases = utils_lib.tests_discover(args)
    if args.is_listcase:
        i = 1
        for case in found_cases:
            print("Case: {} ({}/{})".format(case, i, len(found_cases)))
            i+=1
        print("Total case num: %s"%len(found_cases))
        sys.exit(0)
    if args.is_clean:
        logdir = args.logdir
        if logdir is None:
            print("Please specify --logdir if you want to do cleanup")
            sys.exit(0)
        amis_file = logdir + '/images.json'
    else:
        logdir, amis_file = utils_lib.prepare_dir(args)
    sum_log = "{}/sum.json".format(logdir)
    resource_file = "{}/resource.json".format(logdir)
    if not args.is_clean:
        shutil.copy(amis_file, resource_file )
    ec2_profile = 'default'
    with open(amis_file) as fh:
        try:
            amis_dict = json.load(fh)
        except json.decoder.JSONDecodeError as exc:
            print("Failed to load {}. Please check manually".format(amis_file))
            sys.exit(1)
        for ami in amis_dict:
            ts = resource_class.BaseTest()
            ts.info = ami
            ts.logdir = logdir
            ts.sumlog = sum_log
            if ts.info['region'].startswith('us-gov'):
                ec2_profile = 'aws-us-gov'
            elif ts.info['region'].startswith('cn-'):
                ec2_profile = 'aws-china'
            else:
                ec2_profile = 'aws'
            ts.profile_name = ec2_profile
            ts.resource_file = resource_file
            ALL_TS.append(ts)

    print("Use profile:{}".format(ec2_profile))
    print("resource {}".format(resource_file))
    if args.is_clean:
        with open(resource_file,'r') as fh:
            resource = json.load(fh)
            for r in resource:
                if 'instance_id' in r.keys():
                    instance_id = r['instance_id']
                    region = r['region']
                    ami_id = r['ami']
                    for ts in ALL_TS:
                        if ts.info['ami'] == ami_id:
                            init_ts_vm(ts, instance_id=instance_id)
                            if ts.vm is not None:
                                ts.vm.delete(wait=False)
        sys.exit(0)
    #aws_lib.aws_check_all_regions(profile=ec2_profile, is_paralle=args.is_paralle, resource_file=resource_file)
    region_missed, region_uploaded = aws_lib.aws_find_region_missed(profile=ec2_profile, resource_file=resource_file)
    if not os.path.exists(sum_log):
        with open(sum_log, 'w+') as fh:
            json.dump([], fh, indent=4)
    i = 1

    for case in found_cases:
        print("Running {} ({}/{})".format(case, i, len(found_cases)))
        case_run = eval(case)
        i+=1
        for ts in ALL_TS:
            ts.casename = case
            ts.debuglog = "{}/debug/{}_{}.log".format(logdir, ts.info["ami"], case)
            ts.log.logfile = ts.debuglog

        # run test in paralle or sequence
        if args.is_paralle:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                all_jobs = {executor.submit(case_run, ts): ts for ts in ALL_TS if 'stage0' in ts.casename or ts.vm is not None}
                for r in concurrent.futures.as_completed(all_jobs,  timeout=1200):
                    ts = all_jobs[r]
                    try:
                        data = r.result()
                    except FailException as exc:
                        pass
                    except SkipException as exc:
                        pass
                    except Exception as exc:
                        #traceback.print_exc()
                        #print("{} generated an exception: {}".format(r,exc))
                        ts.fail(traceback.format_exc(), is_raise=False)
                    else:
                        pass
        else:
            for ts in ALL_TS:
                try:
                    if ts.vm is None and 'stage0' not in ts.casename:
                        ts.skipTest("Cannot create instance in {}".format(ts.info['region'], is_raise=False ))
                    if ts.ssh_client is None and 'stage0' not in ts.casename:
                        ts.skipTest("Cannot make ssh connection in {}".format(ts.info['region'], is_raise=False))
                    case_run(ts)
                except FailException as exc:
                    pass
                except SkipException as exc:
                    pass
                except Exception as exc:
                    ts.fail(traceback.format_exc(), is_raise=False)
        for ts in ALL_TS:
            ts.load_resource()
            if 'instance_types_list' in ts.resource_info.keys() and len(ts.resource_info['instance_types_list']) == 0:
                ts.skipTest("No supported instance in {}".format(ts.info['region']), is_raise=False)
                continue
            if ts.vm is None and 'instance_types_list' in ts.resource_info.keys():
                ts.skipTest("Cannot create instance in {}".format(ts.info['region']), is_raise=False)
                continue
            if ts.vm is None and 'stage0' not in ts.casename:
                ts.skipTest("skip as instance not created {}".format(ts.info['region']), is_raise=False)
                continue
            if ts.ssh_client is None and 'instance_types_list' in ts.resource_info.keys():
                ts.skipTest("Cannot make ssh connection in {}".format(ts.info['region']), is_raise=False)
                continue
        # save tests result
        for ts in ALL_TS:
            ts.log.info('Finish {} {} {} result:{}'.format(ts.info["region"], ts.info["ami"], ts.casename, ts.result))
            ts.sum_log(result=ts.result, error=ts.error)
            #print("{}:{}:{}".format(ts.info['ami'],ts.casename,ts.result))
            ts.result = 'PASS'
            ts.error = ''
    print("Total case num:{} Tested AMIs:{}".format(len(found_cases), len(ALL_TS)))
    print("Log dir:{}".format(logdir))
    utils_lib.write_html(sum_log, region_missed=region_missed, region_uploaded=region_uploaded)
    print("Please wait resource cleanup done......")
    cleanup_paralle(ALL_TS)

if __name__ == "__main__":
    main()
