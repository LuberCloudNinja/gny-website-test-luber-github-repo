from constructs import Construct
from aws_cdk import (
    Stage
)
from .gny_website_stack import VGnyWebsiteStack


class PipelineStage(Stage):

    def __init__(self, scope: Construct, id: str, env, region, env_type, cidr, db_name, rds_instance_type, db_proxy_name, tgw_id, cfn_cache_cluster_instance_type, instance_type, ssh_key_pair, aws_account_num, default_action, aws_managed_prefixlist_for_cloudfront, github_owner, github_repo_name, github_branch_name, secrets_manager_github_token, **kwargs):
        super().__init__(scope, id, env=env, **kwargs)

        """ Add CDK/CFN Stacks below. """
        # VGnyWebsiteStack Stack:
        gny_website_vpc = VGnyWebsiteStack(
            self, "gny-website-vpc", env=env, region=region, env_type=env_type, cidr=cidr, db_name=db_name, rds_instance_type=rds_instance_type, db_proxy_name=db_proxy_name, tgw_id=tgw_id, cfn_cache_cluster_instance_type=cfn_cache_cluster_instance_type, instance_type=instance_type, ssh_key_pair=ssh_key_pair, aws_account_num=aws_account_num, default_action=default_action, aws_managed_prefixlist_for_cloudfront=aws_managed_prefixlist_for_cloudfront, github_owner=github_owner, github_repo_name=github_repo_name, github_branch_name=github_branch_name, secrets_manager_github_token=secrets_manager_github_token)
