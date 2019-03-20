## Summary

A shell tool for injecting an AWS profile's credentials into your shell's environment variables. If your AWS profile uses an `role_arn` value, then the role is assumed first.

## Installing

```
$> pip install git+https://github.com/kernelpanek/aws_creds_to_env
```

## Usage

Assuming an example of your `~/.aws/config` file:
```bash
[profile dev]
source_profile = dev
region = us-west-2

[profile prod]
role_arn = arn:aws:iam::999999999999:role/kubernetes_admin
source_profile = prod
region = us-west-2
assume_role_ttl = 3h
```

```
$> chrenv dev
```

```
$> chrenv prod
```
