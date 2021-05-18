import setuptools
import os

setuptools.setup(
    name="ami-val",
    version="0.0.8",
    author="Xiao Liang",
    author_email="xiliang@redhat.com",
    description="AMI validation tool",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/liangxiao1/ami-val",
    #packages=setuptools.find_packages(),
    packages=[ 'ami_val', 'ami_val.tests', 'ami_val.libs'],
    package_data={
        'ami_val': [
            'cfg/*',
            'data/*',
            'scripts/*',
            'templates/*'
        ]
    },
    include_package_data=True,
    #data_files=[('/'+os.path.expanduser("~"), ['cfg/os-tests.yaml']),],
    install_requires=['PyYAML', 'tipset', 'filelock', 'awscli', 'boto3', 'paramiko-fork', 'Jinja2'],
    license="GPLv3+",
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        "Programming Language :: Python :: 3",
        'Operating System :: POSIX',

    ],
    python_requires='>=3.6',
    entry_points = {
             'console_scripts': [
                 'ami-val = ami_val.ami_val:main',
             ],
         },
)
