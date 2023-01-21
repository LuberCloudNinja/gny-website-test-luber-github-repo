#!/bin/bash
# TODO: Change AWS Profile when we get that access.

# Bootrapping AWS Account so CDK can send all fine to the artifact bucket, where all the configurations and permissions are stored.
cdk bootstrap --cloudformation-execution-policies'arn:aws:iam::aws:policy/AdministratorAccess' --profile lhay
