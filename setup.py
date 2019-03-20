from setuptools import setup, find_packages

setup(
    name='aws_cred_to_env',
    version='0.1',
    packages=find_packages(exclude=['tests*']),
    license='MIT',
    description='Export your AWS profile credentials to your environment.',
    long_description=open('README.md').read(),
    install_requires=['awscli', 'boto3'],
    scripts=['bin/chrenv'],
    url='https://github.com/kernelpanek/aws_creds_to_env',
    author='Kernel Panek',
    author_email='kernelpanek@gmail.com'
)
