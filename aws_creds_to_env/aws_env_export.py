#!/usr/bin/env python
import configparser
import argparse
import os
import sys
import boto3
from subprocess import check_output
import socket
import getpass

hostname = socket.gethostname()
username = getpass.getuser()

AWS_CREDENTIALS_PATH = "~/.aws/credentials"
AWS_CONFIG_PATH = "~/.aws/config"


def execute_cmd(cmd):
    check_output(cmd, shell=True)


def aws_environs(args, unk_args, config, credentials):
    profile_info = dict()

    config_profile_name = "profile {}".format(args.profile)
    credential_section_reference = args.profile

    if config.has_section(config_profile_name):
        credential_section_reference = config.get(config_profile_name,
                                                  "source_profile")

    if credentials.has_section(credential_section_reference):
        profile_info.update(
            AWS_PROFILE=args.profile,
            AWS_DEFAULT_PROFILE=args.profile,
            AWS_ACCESS_KEY_ID=credentials.get(credential_section_reference,
                                              "aws_access_key_id"),
            AWS_SECRET_ACCESS_KEY=credentials.get(credential_section_reference,
                                                  "aws_secret_access_key"),
        )
        if credentials.has_option(credential_section_reference,
                                  "aws_session_token"):
            profile_info.update(
                AWS_SESSION_TOKEN=credentials.get(credential_section_reference,
                                                  "aws_session_token"),)

    if config.has_section(config_profile_name):
        if config.has_option(config_profile_name, "region"):
            profile_info.update(
                AWS_DEFAULT_REGION=config.get(config_profile_name,
                                              "region"))
        elif config.has_option("default", "region"):
            profile_info.update(
                AWS_DEFAULT_REGION=config.get("default",
                                              "region"))

        for opt in config.options(config_profile_name):
            if opt.startswith("_"):
                execute_cmd(config.get(config_profile_name, opt))

    if config.has_option(config_profile_name, "role_arn"):
        role_arn = config.get(config_profile_name,
                              "role_arn")

        try:
            sess = boto3.session.Session(profile_name=args.profile)
            sts_client = sess.client("sts")
            sts_result = sts_client.assume_role(RoleArn=role_arn,
                                                RoleSessionName="{u}-{h}".format(u=username, h=hostname),
                                                DurationSeconds=3600)
            sts_creds = sts_result.get("Credentials")
            profile_info.update(
                AWS_ACCESS_KEY_ID=sts_creds.get("AccessKeyId"),
                AWS_SECRET_ACCESS_KEY=sts_creds.get("SecretAccessKey"),
                AWS_SESSION_TOKEN=sts_creds.get("SessionToken"),
                AWS_ROLE_ASSUMPTION_TIMEOUT=sts_creds.get("Expiration").isoformat()
            )
        except Exception:
            sys.stderr.write("Role could not be assumed.")
    return profile_info


def main(args, unk_args):
    credentials = configparser.ConfigParser()
    credentials.read(os.path.expanduser(args.credentials_file))
    config = configparser.ConfigParser()
    config.read(os.path.expanduser(args.config_file))

    extra_env_dict = aws_environs(args, unk_args, config, credentials)
    current_shell = os.environ.get("SHELL")
    os.spawnvpe(os.P_WAIT,
                current_shell,
                [current_shell, ],
                dict(os.environ, **extra_env_dict))


def parse_cli_args(args):
    """
    Parse arguments
    """
    p = argparse.ArgumentParser(description="AWS Environment")
    p.add_argument("--credentials",
                   dest="credentials_file",
                   type=str,
                   required=False,
                   default=AWS_CREDENTIALS_PATH,
                   help="Path to AWS credentials file")
    p.add_argument("--config",
                   dest="config_file",
                   type=str,
                   required=False,
                   default=AWS_CONFIG_PATH,
                   help="Path to AWS config file")
    p.add_argument("profile",
                   type=str,
                   help="AWS Profile Name")
    return p.parse_known_args(args)


if __name__ == "__main__":
    try:
        args, args_other = parse_cli_args(None)
    except Exception as ex:
        print(ex)
        sys.exit(0)

    try:
        main(args, args_other)
    except Exception as main_ex:
        print(main_ex)
    finally:
        sys.exit(0)
