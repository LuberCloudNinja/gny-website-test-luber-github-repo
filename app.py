#!/usr/bin/env python3
import os

import aws_cdk as cdk

from gny_website.gny_website_stack import GnyWebsiteStack
# from gny_website.pipeline_stack import PipelineStack
app = cdk.App()

######################### ENVIRONMENT VARIABLES #########################
env_type = cdk.Environment(
    region=app.node.try_get_context("envs")["env_name_type"])

cidr = cdk.Environment(
    region=app.node.try_get_context("envs")["vpc_cidr"])

db_name = cdk.Environment(
    region=app.node.try_get_context("envs")["dbname"])

db_proxy_name = cdk.Environment(
    region=app.node.try_get_context("envs")["db_proxy_name"])

cfn_cache_cluster_instance_type = cdk.Environment(
    region=app.node.try_get_context("envs")["cfn_cache_cluster_instance_type"])

rds_instance_type = cdk.Environment(
    region=app.node.try_get_context("envs")["rds_instance_type"])

tgw_id = cdk.Environment(region=app.node.try_get_context("envs")["tgw_id"])

ami_id = cdk.Environment(region=app.node.try_get_context("envs")["ami_id"])

ssh_key_pair = cdk.Environment(
    region=app.node.try_get_context("envs")["ssh_key_pair"])

instance_type = cdk.Environment(
    region=app.node.try_get_context("envs")["instance_type"])

aws_prod_account_num = cdk.Environment(
    region=app.node.try_get_context("envs")["account"])

aws_prod_region = cdk.Environment(
    region=app.node.try_get_context("envs")["region"])

aws_prod_default_action = cdk.Environment(
    region=app.node.try_get_context("envs")["default_action"])

aws_managed_prefixlist_for_cloudfront = cdk.Environment(
    region=app.node.try_get_context("envs")["aws_managed_prefixlist_for_cloudfront"])

github_owner = cdk.Environment(
    region=app.node.try_get_context("envs")["github_owner"])

github_repo_name = cdk.Environment(
    region=app.node.try_get_context("envs")["github_repo_name"])

github_branch_name = cdk.Environment(
    region=app.node.try_get_context("envs")["github_branch_name"])

secrets_manager_github_token = cdk.Environment(
    region=app.node.try_get_context("envs")["secrets_manager_github_token_secret"])

secrets_manager_gitbucket_token = cdk.Environment(
    region=app.node.try_get_context("envs")["gny_website_bitbucket_oauth_token"])
######################### ENV: ACCOUNT & REGION: #########################

prod_env = cdk.Environment(
    account=aws_prod_account_num, region=aws_prod_region)

env_prod = prod_env


######################### CALLING STACKS: #########################

""" Please Create SSH-Key Pair before deploying this stack/s """
GnyWebsiteStack(app, "GnyWebsiteStack", env_type=env_type,
                cidr=cidr, db_name=db_name, rds_instance_type=rds_instance_type, db_proxy_name=db_proxy_name, tgw_id=tgw_id, cfn_cache_cluster_instance_type=cfn_cache_cluster_instance_type, instance_type=instance_type, ssh_key_pair=ssh_key_pair, aws_account_num=aws_prod_account_num, env_prod=env_prod, default_action=aws_prod_default_action, aws_managed_prefixlist_for_cloudfront=aws_managed_prefixlist_for_cloudfront, github_owner=github_owner, github_repo_name=github_repo_name, github_branch_name=github_branch_name, secrets_manager_github_token=secrets_manager_github_token, secrets_manager_gitbucket_token=secrets_manager_gitbucket_token)


# prod = PipelineStack(app, "GnyWebsiteStack", env_type=env_type,
#                      cidr=cidr, db_name=db_name, rds_instance_type=rds_instance_type, db_proxy_name=db_proxy_name, tgw_id=tgw_id, cfn_cache_cluster_instance_type=cfn_cache_cluster_instance_type, instance_type=instance_type, ssh_key_pair=ssh_key_pair, aws_account_num=aws_prod_account_num, env=env_prod, default_action=aws_prod_default_action, aws_managed_prefixlist_for_cloudfront=aws_managed_prefixlist_for_cloudfront, github_owner=github_owner, github_repo_name=github_repo_name, github_branch_name=github_branch_name, secrets_manager_github_token=secrets_manager_github_token)
######################### CALLING STACKS: #########################

app.synth()
