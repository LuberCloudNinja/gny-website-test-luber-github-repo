from constructs import Construct
from aws_cdk import (
    Stack,
    aws_codecommit as codecommit,
    pipelines as pipelines,
)
# We need the "import aws_cdk as cdk" module to deploy stages across multiple accounts/regions.
import aws_cdk as cdk
from .pipeline_stage import PipelineStage

# NOTE: CREATE THE VSC FROM CODECOMIT & THEN COMMIT & PUSH TO THE REPO, THEN DO CDK DEPLOY ONLY ONCE.


class PipelineStack(Stack):
    def __init__(self, scope: Construct, id: str, env_type, cidr, db_name, rds_instance_type, db_proxy_name, tgw_id, cfn_cache_cluster_instance_type, instance_type, ssh_key_pair, aws_account_num, env, default_action, aws_managed_prefixlist_for_cloudfront, github_owner, github_repo_name, github_branch_name, secrets_manager_github_token, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        # NOTE: The "get_env" variable is needed to pull the environments from cdk.json. Please create this in this pipeline stack instead of the main stack the "app.py."
        get_env = self.node.try_get_context("envs")
        # NOTE: Creates a CodeCommit repository called 'WorkshopRepo' Skip this if using GitHub or using an exisiting CodeCommit Repo:
        # NOTE: IF CREATING THE REPO FROM STRATCH IN CODECOMIT MAKE SURE TO CREAT COMMIT & PUSH TO THE REPO, THEN DO CDK DEPLOY ONLY ONCE. COMMENT OUT EVERYTHING BEFORE CREATING THE REPO, AGAIN, ONLY IF CREATING A NEW REPO IN CODECOMMIT.
        # repo = codecommit.Repository(
        #     self, "CodePipeLine-For-Patching-Effort", repository_name="CodePipeLine-Patching-Environments"
        # )

        # NOTE: Create the above repo before creating the below pipeline:
        pipeline = pipelines.CodePipeline(
            self,
            "Pipeline",
            # NOTE: Encrypt artifacts, required for cross-account deployments.
            cross_account_keys=True,
            synth=pipelines.ShellStep(
                "Synth",
                input=pipelines.CodePipelineSource.code_commit(  # Add the from_repository_name method source your code from an existing repo, in this case is Operations.
                    repository=codecommit.Repository.from_repository_name(self,
                                                                          "gny_website_repo", repository_name="gny_website_repo"), branch="main"),
                commands=[
                    "npm install -g aws-cdk",  # NOTE: Installs the cdk cli on Codebuild
                    "ls -ltr",
                    "pwd",
                    # NOTE: Instructs Codebuild to install required packages:
                    "pip install -r requirements.txt",
                    # NOTE: CDK synthesize the our python script into json before creating the cfn stack.
                    "npx cdk synth",
                ],  # NOTE: Please bootstrap the project again with the fallowing command before and after adding the below line: "cdk bootstrap --cloudformation-execution-policies'arn:aws-us-gov:iam::aws:policy/AdministratorAccess' --profile lhay"
                # NOTE: We had to enforce the "primary_output_directory='enforce-tagging-autoremediation/cdk.out/' to tell CodeBuild post build phase where to find the cdk.out which in our case is at the root dir "enforce-tagging-autoremediation".
                primary_output_directory='cdk.out/'
            ),
        )


# ***********************************************STAGES***********************************************
        """ Add wave() & stages() methods below: """
        # NOTE: If you want to create stacks across multiple accounts/regions and run the deploy stage in
        # parallele then use "pipeline.add_wave()" method, instead of pipeline.stage(). However, know that if you add another add_wave() method the the stages in it will not deploy in paralle with the other stages inside an other add_wave(), the parall deployments is only within the stages using the same add_wave() method :). E.G Using stage()
        # method instead of wave() method:  :)

        # Fist deployment was done with the pipeline.add_stage(), E.G below, but lets "not" use it again to create it to start with.:

# *********************************************** us-east-1 ***********************************************
# *********************************************** STAGES ***********************************************
        # ************** lhay **************
        # NOTE: If you want more stages just add another add_wave() method to the project, and then add the add_stage() for the account or region where you'd like the stage to be deployed.
        us_east_1_wave = pipeline.add_wave("us-east-1")

        # NOTE: Instantiating the stage module below with all the accounts where we will be deploying the stacks:

        # ************** lhay **************
        us_east_1_wave.add_stage(PipelineStage(
            self, "lhay", env=env.region.account, region=env.region.region, env_type=env_type, cidr=cidr, db_name=db_name, rds_instance_type=rds_instance_type, db_proxy_name=db_proxy_name, tgw_id=tgw_id, cfn_cache_cluster_instance_type=cfn_cache_cluster_instance_type, instance_type=instance_type, ssh_key_pair=ssh_key_pair, aws_account_num=aws_account_num, default_action=default_action, aws_managed_prefixlist_for_cloudfront=aws_managed_prefixlist_for_cloudfront, github_owner=github_owner, github_repo_name=github_repo_name, github_branch_name=github_branch_name, secrets_manager_github_token=secrets_manager_github_token))
