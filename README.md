# ami-val

## Introduction

ami-val is a lightweight, fast tests collection for AMIs.

## Installation

### Install from pip

`# pip3 install ami-val`

### Install from source code

```bash
# git clone https://github.com/liangxiao1/ami-val.git
# cd ami-val
# python3 setup.py install
```

### Build wheel from source code and install it

```bash
# python3 setup.py sdist bdist_wheel
# pip install -U dist/ami_val-0.0.1-py3-none-any.whl
```

### Public new wheels on [pypi](https://pypi.org/project/ami-val/) (maintainer use only)

`# python3 -m twine upload  dist/*`

## Run test

### We shared the pre configured aws credentials in "~/.aws/", please specify profile name as below format

```bash
# cat ~/.aws/credentials
# aws for default aws regions access
[aws]
aws_access_key_id = xxxxxxx
aws_secret_access_key = xxxxxxxxx
# aws for default china regions access
[aws-china]
aws_access_key_id = xxxxxxx
aws_secret_access_key = xxxxxxxxx
# aws for default us-gov regions access
[aws-us-gov]
aws_access_key_id = xxxxxxx
aws_secret_access_key = xxxxxxxxx

```

### The config file

You can change the default setting in "cfg/ami-val.yaml" locates in the same installed dir.

Below option is must required for ssh login:
```
# remote_user: user and keyfile to login instance
ssh_user: ec2-user
ssh_keyfile: '/home/virtqe_s1.pem'
# if pair_name keypair not found, will upload ssh_pubfile automatically
# ssh_pubfile is not required if pair_name exists already.
pair_name: virtqe_s1
ssh_pubfile: '/home/virtqe_s1.pub'
```

### Run all ami-val supported cases(the default path is "/usr/local/bin" if not in virtual environment. )  

`# ami-val -f https://xxxx/pub/task/343012 --paralle`  
`# ami-val -f images.json`  

The json format should be like this, except required, other are options:

```bash
# cat images.json
[
  {
    "ami": "ami-01166axxxxxx", <- required
    "description": "Provided by Red Hat, Inc.",
    "ena_support": true, <- required
    "name": "RHEL-xxxxxx-x86_64-1-Hourly2-GP2", <- required
    "region": "us-east-1", <- required
    "release": {
      "arch": "x86_64", <- required
      "base_product": null, 
      "base_version": null, 
      "date": "20201020", 
      "product": "RHEL", 
      "respin": 1, 
      "type": null, 
      "variant": "BaseOS", 
      "version": "8.x"
    }, 
    "root_device": "/dev/sda1", 
    "sriov_net_support": "simple", 
    "type": "hourly", 
    "virtualization": "hvm", 
    "volume": "gp2"
  }
]
```

### List all supported cases only without run

`# ami-val -l`

#### Filter case name with keywords timezone and bash

`# ami-val -l -p timezone,bash_history`

#### Filter case name with keywords stage1 and skip timezone check

`# ami-val -l -p stage1 -s timezone`

### Clean the resource created  
```bash
# ami-val --logdir /tmp/ami_val_344423 --clean
```

### The log file

The console only shows the case test run.
The test debug log file are saved in "/tmp/ami_val" following case name by default.
If task id can be detected, it will be in "/tmp/ami_val_taskid" by default.

Below is an example:

```bash
# ami-val -f https://xxxxxxx/pub/task/343012 --paralle
Run in mode: is_listcase:False pattern:None is_paralle:True
Task url provided, try to download it
Get data from http://xxxxxxx/pub/task/343012/log/images.json?format=raw
Got data from http://xxxxxxx/pub/task/343012/log/images.json?format=raw
Remove exists /tmp/ami_val_343012
Create new /tmp/ami_val_343012
Data saved to /tmp/ami_val_343012/images.json
Use profile:aws
resource /tmp/ami_val_343012/resource.json
2021-03-01 01:41:30.068325 INFO:Use profile:aws in region ['us-west-2', 'cn-northwest-1', 'us-gov-west-1']
2021-03-01 01:41:30.544445 INFO:Init key in region us-west-2 successfully
Running ami_val.tests.test_stage0.test_stage0_check_aminame (1/6)
Running ami_val.tests.test_stage0.test_stage0_check_ena_enabled (2/6)
Running ami_val.tests.test_stage0.test_stage0_launch_instance (3/6)
Running ami_val.tests.test_stage1.test_stage1_check_bash_history (4/6)
Running ami_val.tests.test_stage1.test_stage1_check_username (5/6)
Running ami_val.tests.test_stage2.test_stage2_check_ha_specific (6/6)
Total case num: 6
Log dir:/tmp/ami_val_343012
HTML summary:/tmp/ami_val_343012/sum.html
Please wait resource cleanup done......

```

### The installed files

All test files are located in "ami_val/tests" directory.

```bash
# pip3 show -f ami-val|grep -v _pycache|grep -v dist
Name: ami-val
Version: 0.0.1
Summary: AMI validation tool
Home-page: https://github.com/liangxiao1/ami-val
Author: Xiao Liang
Author-email: xiliang@redhat.com
License: GPLv3+
Location: /home/p3_os_env/lib/python3.6/site-packages
Requires: PyYAML, filelock, awscli, boto3, tipset, argparse
Required-by: 
Files:
  ../../../bin/ami-val
  ami_val/__init__.py
  ami_val/ami_val.py
  ami_val/ami_val_run.py
  ami_val/cfg/ami-val.yaml
  ami_val/cfg/os-tests.yaml
  ami_val/data/baseline_log.json
  ami_val/data/results.html
  ami_val/libs/__init__.py
  ami_val/libs/aws_lib.py
  ami_val/libs/resource_class.py
  ami_val/libs/rmt_ssh.py
  ami_val/libs/utils_lib.py
  ami_val/scripts/rhel-ha-aws-check.sh
  ami_val/tests/__init__.py
  ami_val/tests/test_stage0.py
  ami_val/tests/test_stage1.py
  ami_val/tests/test_stage2.py

```

### Contribution

You are welcomed to create pull request or raise issue. New case from real customer senario or rhbz is prefered.
