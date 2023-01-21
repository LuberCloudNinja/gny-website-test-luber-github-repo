from aws_cdk import (
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_ssm as ssm,
    aws_kms as kms,
    aws_iam as iam,
    aws_secretsmanager as sm,
    aws_elasticache as elasticache,
    aws_efs as efs,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_wafv2 as waf,
    aws_codebuild as codebuild,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as codepipeline_actions,
    aws_s3 as s3,
    RemovalPolicy,
    Stack)
from aws_cdk import pipelines
from constructs import Construct
import aws_cdk as cdk


############### PURPOSE ###############

""" This stack will deploy a two/three tier web app. """

############### PURPOSE ###############


########################################### NOTES NOTES NOTES ###########################################

# 1: If you want to delete this stack, you'll need to manually delete RDS and EFS, these two resources has a retain policy.
#  After that you can delete the VPC using "cdk destroy stackname", however after five minutes you'll need to manually delete the vpc manually.

# 2: Test mysql access pointing to the RDS Proxy endpoints "get secret from secrets manager":
# mysql -h gny-website-prod-rdsproxy.proxy-cw6m2qusdscb.us-east-1.rds.amazonaws.com -P 3306 -u admin -p

# 3: We need to create a Github session token and then sotre it in SSM. We need to do this to authenticate with GitHub.
# Please store the toketn in SSM and create it manually in SSM (Not with CDK.)

# 4: Please Create SSH-Key Pair before deploying this stack/s.
########################################### NOTES NOTES NOTES ###########################################


class GnyWebsiteStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, env_type, cidr, db_name, rds_instance_type, db_proxy_name, tgw_id, cfn_cache_cluster_instance_type, instance_type, ssh_key_pair, aws_account_num, env_prod, default_action, aws_managed_prefixlist_for_cloudfront, github_owner, github_repo_name, github_branch_name, secrets_manager_github_token, secrets_manager_gitbucket_token, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

######################### NETWORKING #########################

        """ Creating VPC """
        self.vpc = ec2.Vpc(self, f"{env_type.region}-prodVPC",
                           cidr=cidr.region,
                           max_azs=2,
                           enable_dns_support=True,
                           enable_dns_hostnames=True,
                           subnet_configuration=[
                               ec2.SubnetConfiguration(
                                   name="Public",
                                   subnet_type=ec2.SubnetType.PUBLIC,
                                   cidr_mask=27
                               ),
                               ec2.SubnetConfiguration(
                                   name="Application",
                                   subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
                                   cidr_mask=27
                               ),
                               ec2.SubnetConfiguration(
                                   name="Data",
                                   subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                                   cidr_mask=27
                               )
                           ],
                           nat_gateways=2
                           )

        """ Getting private subnets in a list: """
        priv_subnets = [
            subnet.subnet_id for subnet in self.vpc.private_subnets]

        """ TGW ATTACHMENT: """
        cfn_transit_gateway_attachment = ec2.CfnTransitGatewayAttachment(self, f"{env_type.region}-TransitGatewayAttachment",
                                                                         subnet_ids=[
                                                                             subnet.subnet_id for subnet in self.vpc.isolated_subnets],
                                                                         # TODO: PLEASE ADD THE CORRECT TGW ID.
                                                                         transit_gateway_id=tgw_id.region,
                                                                         vpc_id=self.vpc.vpc_id)

        # ADDING TWO MAINS HOLD SO THE TGW ATTACHMENTS GETS CREATED SO THE ROUTES BELOW CAN FIND THE TWG

        """ Add Custom Routes To All Subnets using Python List Comprehension: """

        # Custom Routes to Data Subnets:
        for num, subnet in enumerate(self.vpc.isolated_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-data-1-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.120.0/24',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        for num, subnet in enumerate(self.vpc.isolated_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-data-2-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.130.0/24',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        for num, subnet in enumerate(self.vpc.isolated_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-data-3-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/16',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        # Custom Routes to Application Subnets:
        for num, subnet in enumerate(self.vpc.private_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-app-1-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.120.0/24',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        for num, subnet in enumerate(self.vpc.private_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-app-2-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.130.0/24',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        for num, subnet in enumerate(self.vpc.private_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-app-3-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/16',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        # Custom Routes to Public Subnets:
        for num, subnet in enumerate(self.vpc.public_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-public-1-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        for num, subnet in enumerate(self.vpc.public_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-public-2-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.130.0/24',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

        for num, subnet in enumerate(self.vpc.public_subnets, start=1):
            data_routes = ec2.CfnRoute(
                self,
                id=f"{env_type.region}-public-3-sent-traffict-onpremise-{num}",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/16',
                # TODO: PLEASE ADD THE CORRECT TGW ID in cdk.json.
                transit_gateway_id=tgw_id.region
            )
            data_routes.node.add_dependency(cfn_transit_gateway_attachment)

######################### SECURITY #########################

        ##### SECURITY GROUPS #####
        """ ALB SG: """

        self.gny_website_alb_sg = ec2.SecurityGroup(self, f"{env_type.region}-alb",
                                                    vpc=self.vpc,
                                                    description=f"SG for ALB group {env_type.region}",
                                                    security_group_name=f"{env_type.region}-alb-sg",
                                                    )
        # Add Inbound Rules to Allow any ip from the internet as tcp port 80:

        # self.gny_website_alb_sg.add_ingress_rule(
        #     ec2.Peer.any_ipv4(), ec2.Port.tcp(port=80), description="Allow http port 80 from 0.0.0.0/0")

        # Add a AWS Managed Prefix List to allow only Cloudfront Global IP Spaces to connect to ALB using port 80:

        aws_managed_prefixlist_for_cloudfront = ec2.Peer.prefix_list(
            aws_managed_prefixlist_for_cloudfront.region)

        self.gny_website_alb_sg.add_ingress_rule(
            aws_managed_prefixlist_for_cloudfront, ec2.Port.tcp(80), description="Allow inbound HTTP traffic from CDN/Cloudfront Global address space.")

        """ ASG SECURITY GROUP:"""
        self.gny_website_asg_sg = ec2.SecurityGroup(self, f"{env_type.region}",
                                                    vpc=self.vpc,
                                                    description=f"SG for ASG group {env_type.region}",
                                                    security_group_name=f"{env_type.region}-asg-sg"
                                                    )

        # Add Inbound Rules to Allow ASG SG to tcp port 80:

        self.gny_website_asg_sg.connections.allow_from(
            self.gny_website_alb_sg, port_range=ec2.Port.tcp(80))

        # RDS Proxy SG:
        self.gny_website_rds_proxy_sg = ec2.SecurityGroup(self, f"{env_type.region}-rds-proxy",
                                                          vpc=self.vpc,
                                                          description=f"SG for {env_type.region} RDS Proxy",
                                                          security_group_name=f"{env_type.region}-rds-proxy-sg"
                                                          )
        self.gny_website_rds_proxy_sg.connections.allow_from(
            self.gny_website_asg_sg, port_range=ec2.Port.tcp(3306))

        # Elasticache Cluster SG:
        self.gny_website_rds_elasticache_sg = ec2.SecurityGroup(self, f"{env_type.region}-elasticache",
                                                                vpc=self.vpc,
                                                                description=f"SG for {env_type.region} Elasticache Cluster",
                                                                security_group_name=f"{env_type.region}-elasticache-sg"
                                                                )
        self.gny_website_rds_elasticache_sg.connections.allow_from(
            self.gny_website_asg_sg, port_range=ec2.Port.tcp(11211))

        # EFS SG:
        self.gny_website_efs_sg = ec2.SecurityGroup(self, f"{env_type.region}-efs",
                                                    vpc=self.vpc,
                                                    description=f"SG for {env_type.region} efs",
                                                    security_group_name=f"{env_type.region}-efs-sg"
                                                    )
        self.gny_website_efs_sg.connections.allow_from(
            self.gny_website_asg_sg, port_range=ec2.Port.tcp(2049))

        ##### KMS #####
        """ RDS KMS """
        self.kms_rds = kms.Key(self, f"{env_type.region}-RDSKey",
                               enable_key_rotation=True,
                               description=f"{env_type.region}-key-rds", enabled=True, removal_policy=RemovalPolicy.DESTROY)

        self.kms_rds.add_alias(alias_name=(
            f'alias-{env_type.region}-key-rds'))

        """ ASG/EC2 KMS """
        self.kms_ec2 = kms.Key(self, f"{env_type.region}-ASG-EC2Key",
                               enable_key_rotation=True,
                               description=f"{env_type.region}-key-ec2-asg", enabled=True, removal_policy=RemovalPolicy.DESTROY)

        self.kms_ec2.add_alias(alias_name=(
            f'alias-{env_type.region}-key-ec2-asg'))

        """ EFS File System KMS """
        self.kms_efs = kms.Key(self, f"{env_type.region}-EFSKey",
                               enable_key_rotation=True,
                               description=f"{env_type.region}-key-efs", enabled=True, removal_policy=RemovalPolicy.DESTROY)

        self.kms_efs.add_alias(alias_name=(
            f'alias-{env_type.region}-key-efs'))

        # Webserver IAM Role:
        web_server_role = iam.Role(self, f"{env_type.region}-webServerRoleId",
                                   assumed_by=iam.ServicePrincipal(
                                       'ec2.amazonaws.com'),
                                   managed_policies=[
                                       iam.ManagedPolicy.from_aws_managed_policy_name(
                                           'AmazonSSMManagedInstanceCore'
                                       ),
                                       iam.ManagedPolicy.from_aws_managed_policy_name(
                                           'AmazonS3ReadOnlyAccess'
                                       ),
                                       iam.ManagedPolicy.from_aws_managed_policy_name(
                                           'AmazonElasticFileSystemFullAccess'
                                       )
                                   ])


######################### DATA TIER #########################

        """ RDS """
        # Create RDS subnet group:

        self.rds_subnet_group = rds.SubnetGroup(self, id=f"{env_type.region}-rds-subnet-group", description=f"{env_type.region}-rds subnet group",
                                                removal_policy=RemovalPolicy.DESTROY, subnet_group_name=f"{env_type.region}-rds-subnet-group", vpc=self.vpc,
                                                vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED))

        # Create RDS DBs:

        self.db_mysql = rds.DatabaseCluster(self, f"{env_type.region}-mysql",
                                            subnet_group=self.rds_subnet_group,
                                            default_database_name=db_name.region,
                                            cluster_identifier=db_name.region,
                                            engine=rds.DatabaseClusterEngine.aurora_mysql(
                                                version=rds.AuroraMysqlEngineVersion.VER_2_10_1),
                                            credentials=rds.Credentials.from_generated_secret(
                                                'admin'),
                                            instance_props=rds.InstanceProps(vpc=self.vpc, vpc_subnets=ec2.SubnetSelection(
                                                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                                                instance_type=ec2.InstanceType(instance_type_identifier=rds_instance_type.region)),  # TODO: IN PROD PLEASE CHANGE INSTANCE TYPE in ENV.
                                            instances=2,
                                            storage_encryption_key=kms.IKey.add_alias(
                                                self, alias=self.kms_rds),
                                            removal_policy=RemovalPolicy.RETAIN,
                                            deletion_protection=True,
                                            backup=rds.BackupProps(
                                                retention=cdk.Duration.days(7))
                                            )
        self.db_mysql.connections.allow_default_port_from(
            self.gny_website_asg_sg, description="Allow ASG instances to connect to port 3306 (sql) in rds db instances")

        """ Add a RDS Proxy for even faster connection when quering the database """
        # IAM Role is added by the construct. We don't need to create it.
        # The security group is also added by the cdk construct, but it doesn't add inbound rules allowing the ASG SG and Elasticache SG to connect. We need to do it.
        proxy = rds.DatabaseProxy(self, f"{env_type.region}-RDSProxy",
                                  proxy_target=rds.ProxyTarget.from_cluster(
                                      self.db_mysql),
                                  db_proxy_name=db_proxy_name.region,
                                  secrets=[self.db_mysql.secret],
                                  vpc=self.vpc,
                                  vpc_subnets=ec2.SubnetSelection(
                                      subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                                  security_groups=[
                                      self.gny_website_rds_proxy_sg]
                                  )

        # Attach ReadOnly enpoint to the RDS Proxy. By default RDS Proxy comes with a Read/Write endpoint which is not ideal for read intense apps:
        read_only_proxy_endpoint = rds.CfnDBProxyEndpoint(self, f"{env_type.region}-CfnDBProxyEndpoint",
                                                          db_proxy_endpoint_name=f"{env_type.region}-CfnDBProxyEndpoint-ReadOnly",
                                                          db_proxy_name=proxy.db_proxy_name,
                                                          vpc_subnet_ids=[subnet.subnet_id for subnet in self.vpc.isolated_subnets])  # This list comprehention "for loop" will get the data isolated subnets to ther ReadOnly endpoint.

        # Gets AWS Secrets Manager ARN to pass to instances userdata to connect to the DB.
        secret_for_rds_and_rdsproxy = sm.Secret.from_secret_attributes(self, f"{env_type.region}-ImportedSecret",
                                                                       secret_complete_arn=self.db_mysql.secret.secret_arn,
                                                                       # If the secret is encrypted using a KMS-hosted CMK, either import or reference that key:
                                                                       # encryption_key=....
                                                                       )

        """ Elasticache Cluster """

        # Create subnet group:

        self.elasticache_subnet_group = elasticache.CfnSubnetGroup(self, id=f"{env_type.region}-elasticache-subnet-group", description=f"{env_type.region}-elasticache subnet group",
                                                                   cache_subnet_group_name=f"{env_type.region}-elasticache-subnet-group", subnet_ids=[subnet.subnet_id for subnet in self.vpc.isolated_subnets])

        """ Elasticache Cluster """

        # Create ElastiCache for Memcached cluster:
        cfn_cache_cluster = elasticache.CfnCacheCluster(self, f"{env_type.region}-MyCfnCacheCluster",
                                                        # TODO: IN PROD PLEASE CHANGE INSTANCE TYPE.
                                                        cluster_name=f"{env_type.region}-elasticache-cluster",
                                                        cache_node_type=cfn_cache_cluster_instance_type.region,
                                                        engine="Memcached",
                                                        num_cache_nodes=2,
                                                        auto_minor_version_upgrade=False,
                                                        az_mode="cross-az",
                                                        vpc_security_group_ids=[
                                                            str(self.gny_website_rds_elasticache_sg.security_group_id)],
                                                        engine_version="1.5.16",
                                                        cache_subnet_group_name=self.elasticache_subnet_group.cache_subnet_group_name,
                                                        port=3306,
                                                        )
        # Add a DependsOn on "cfn_cache_cluster" for "self.elasticache_subnet_group" to be created:

        cfn_cache_cluster.add_depends_on(self.elasticache_subnet_group)

        """ EFS File System: """

        # Create EFS File System:
        self.file_system = efs.FileSystem(self, f"{env_type.region}-MyEfsFileSystem",
                                          file_system_name=f"{env_type.region}-efs-filesystem",
                                          vpc=self.vpc,
                                          # files are not transitioned to infrequent access (IA) storage by default
                                          lifecycle_policy=efs.LifecyclePolicy.AFTER_90_DAYS,
                                          performance_mode=efs.PerformanceMode.GENERAL_PURPOSE,  # default
                                          security_group=self.gny_website_efs_sg,
                                          enable_automatic_backups=True,
                                          encrypted=True,
                                          removal_policy=RemovalPolicy.RETAIN,
                                          kms_key=kms.IKey.add_alias(
                                              self, alias=self.kms_efs),
                                          vpc_subnets=ec2.SubnetSelection(
                                              subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)
                                          )


######################### APP/WEB TIER #########################

        """" ALB/ASG: """

        # Select AMI and create bootstrap script:

        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            # Update OS.
            "sudo apt-get update -y",
            "sudo apt-get dist-upgrade -y",
            # Install AWS CLIv2
            "sudo apt install awscli -y",
            # Create variable for for mysql secret from secrets manager:

            # Intall packets need it to install the below packets:
            "sudo apt install lsb-release ca-certificates apt-transport-https software-properties-common -y",
            # Install php8.1:
            "sudo mkdir /etc/bootstrap-php-install",
            "cd /etc/bootstrap-php-install",
            "sudo add-apt-repository ppa:ondrej/php -y",
            "sudo apt-get update -y",
            "sudo apt install php8.1 -y",
            "sudo apt install php8.1-cli php8.1-dev -y",
            # Install mysql:
            "sudo apt-get install mysql-server -y",
            "sudo apt install mysql-client -y",
            "mysql -h gny-website-prod-rdsproxy.proxy-cw6m2qusdscb.us-east-1.rds.amazonaws.com -P 3306 -u admin -p"
            # Installing Apache2:
            "apt install -y apache2",
            "systemctl start apache2",
            "cd /var/www/html",
            "mv index.html index-old.html",
            "bash -c \"echo '<?php phpinfo(); ?>' > index.php\"",
            # Install WGET:
            "apt-get install wget -y",
            # Installing the PHP client for Memcached:
            "mkdir /etc/bootstrap-installing-memcached-client-for-elasticache",
            "cd /etc/bootstrap-installing-memcached-client-for-elasticache",
            "wget https: // elasticache-downloads.s3.amazonaws.com/ClusterClient/PHP-8.1/latest-64bit-X86-openssl3",
            "tar -zxvf  latest-64bit-X86-openssl3",
            "cp amazon-elasticache-cluster-client.so /usr/lib/php/20190902",
            "echo 'extension=amazon-elasticache-cluster-client.so' >> /etc/php/8.1/cli/php.ini",
            # Install EFS Client:
            "sudo apt-get install nfs-common -y",
            "sudo su -",
            "mkdir /tmp/efs",
            # Lets mount EFS File System:
            # File System mount is under /tmp/efs
            f"mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport {self.file_system.file_system_id}.efs.us-east-1.amazonaws.com:/ /tmp/efs",

        )
        # RDS and RDS Proxy Secret Value below:
        rds_and_rdsproxy_secret = cdk.SecretValue.secrets_manager(
            secret_id=secret_for_rds_and_rdsproxy.secret_name)

        # Pull Ubuntu AMI from SSM(managed by AWS, patching is also AWS responsability)
        # /aws/service/canonical/ubuntu/server/focal/stable/current/amd64/hvm/ebs-gp2/ami-id
        machine_image = ec2.MachineImage.from_ssm_parameter(
            parameter_name="/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
            os=ec2.OperatingSystemType.LINUX,
            user_data=user_data
        )

        # Create Application Load Balancer:
        alb = elbv2.ApplicationLoadBalancer(
            self,
            f"{env_type.region}-myAlbId",
            vpc=self.vpc,
            internet_facing=True,
            load_balancer_name=f"{env_type.region}-WebServerAlb",
            security_group=self.gny_website_alb_sg
        )

        # Add Listerner to ALB:
        listener = alb.add_listener(f"{env_type.region}-listernerId",
                                    port=80,
                                    open=True)

        # Create AutoScaling Group with 2 EC2 Instances:
        web_server_asg = autoscaling.AutoScalingGroup(self,
                                                      f"{env_type.region}-webServerAsgId",
                                                      vpc=self.vpc,
                                                      vpc_subnets=ec2.SubnetSelection(
                                                          subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT
                                                      ),
                                                      instance_type=ec2.InstanceType(
                                                          instance_type_identifier=instance_type.region),
                                                      machine_image=machine_image,
                                                      key_name=ssh_key_pair.region,
                                                      role=web_server_role,
                                                      min_capacity=2,
                                                      max_capacity=2,
                                                      desired_capacity=2,
                                                      security_group=self.gny_website_asg_sg,
                                                      health_check=autoscaling.HealthCheck.elb(
                                                          grace=cdk.Duration.minutes(5))  # This's the time that it waits for the
                                                      # Instances to install all the sofwares from the userdata, after this time
                                                      # healthchecks will start.
                                                      )

        # Create Target Group:
        listener.add_targets(f"{env_type.region}-target-group", target_group_name=f"{env_type.region}-target-group",
                             port=80, targets=[web_server_asg], health_check=elbv2.HealthCheck(enabled=True, path='/', healthy_http_codes="200"))

        ########### Create WAF (Web ACL) for CDN: ###########

        self.web_acl = waf.CfnWebACL(self, f"{env_type.region}-WAF-ACL",
                                     default_action={
                                         default_action.region: {}},
                                     scope="CLOUDFRONT",
                                     visibility_config={
                                         "sampledRequestsEnabled": True,
                                         "cloudWatchMetricsEnabled": True,
                                         "metricName": "web-acl",
                                     },
                                     rules=[
                                         {
                                             "name": "Custom-RateLimit500",
                                             "priority": 0,
                                             "action": {
                                                 "block": {}
                                             },
                                             "visibilityConfig": {
                                                 "sampledRequestsEnabled": True,
                                                 "cloudWatchMetricsEnabled": True,
                                                 "metricName": "Custom-RateLimit500"
                                             },
                                             "statement": {
                                                 "rateBasedStatement": {
                                                     "limit": 500,
                                                     "aggregateKeyType": "IP"
                                                 }
                                             }
                                         },
                                         {
                                             "priority": 1,
                                             "overrideAction": {"none": {}},
                                             "visibilityConfig": {
                                                 "sampledRequestsEnabled": True,
                                                 "cloudWatchMetricsEnabled": True,
                                                 "metricName": "AWS-AWSManagedRulesAmazonIpReputationList",
                                             },
                                             "name": "AWS-AWSManagedRulesAmazonIpReputationList",
                                             "statement": {
                                                 "managedRuleGroupStatement": {
                                                     "vendorName": "AWS",
                                                     "name": "AWSManagedRulesAmazonIpReputationList",
                                                 },
                                             },
                                         },
                                         {
                                             "priority": 2,
                                             "overrideAction": {"none": {}},
                                             "visibilityConfig": {
                                                 "sampledRequestsEnabled": True,
                                                 "cloudWatchMetricsEnabled": True,
                                                 "metricName": "AWS-AWSManagedRulesCommonRuleSet",
                                             },
                                             "name": "AWS-AWSManagedRulesCommonRuleSet",
                                             "statement": {
                                                 "managedRuleGroupStatement": {
                                                     "vendorName": "AWS",
                                                     "name": "AWSManagedRulesCommonRuleSet",
                                                 },
                                             },
                                         },
                                         {
                                             "priority": 3,
                                             "overrideAction": {"none": {}},
                                             "visibilityConfig": {
                                                 "sampledRequestsEnabled": True,
                                                 "cloudWatchMetricsEnabled": True,
                                                 "metricName": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                                             },
                                             "name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                                             "statement": {
                                                 "managedRuleGroupStatement": {
                                                     "vendorName": "AWS",
                                                     "name": "AWSManagedRulesKnownBadInputsRuleSet",
                                                 },
                                             },
                                         },
                                         {
                                             "priority": 4,
                                             "overrideAction": {"none": {}},
                                             "visibilityConfig": {
                                                 "sampledRequestsEnabled": True,
                                                 "cloudWatchMetricsEnabled": True,
                                                 "metricName": "AWS-AWSManagedRulesSQLiRuleSet",
                                             },
                                             "name": "AWS-AWSManagedRulesSQLiRuleSet",
                                             "statement": {
                                                 "managedRuleGroupStatement": {
                                                     "vendorName": "AWS",
                                                     "name": "AWSManagedRulesSQLiRuleSet",
                                                 },
                                             },
                                         }
                                     ]
                                     )

        ########### CDN with CloudFront: ###########
        # An Elastic Load Balancing (ELB) v2 load balancer may be used as an origin.
        # In order for a load balancer to serve as an origin, it must be publicly accessible (internetFacing is true).
        # Both Application and Network load balancers are supported.

        cdn = cloudfront.Distribution(self, f"{env_type.region}-cloudfront",
                                      default_behavior=cloudfront.BehaviorOptions(
                                          #   Create a cache policy to set all the TTLs to 0 back to the app(dynamic) origins(alb) and attach it to the cdn:
                                            cache_policy=cloudfront.CachePolicy(self, f"{env_type.region}-cdn-cache-policy-ttl0",
                                                                                cache_policy_name=f"{env_type.region}-cdn-cache-policy-ttl0",
                                                                                default_ttl=cdk.Duration.minutes(
                                                                                    0),
                                                                                min_ttl=cdk.Duration.minutes(
                                                                                    0),
                                                                                max_ttl=cdk.Duration.minutes(
                                                                                    0)
                                                                                ),
                                          # Does the same as the above policy we created, but is managed by AWS:
                                          # cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                                          origin=origins.LoadBalancerV2Origin(
                                              alb, origin_shield_region=env_prod.region.region,
                                              http_port=80, protocol_policy=cloudfront.OriginProtocolPolicy.HTTP_ONLY),
                                          viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                                          allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL),
                                      enable_logging=True,
                                      web_acl_id=self.web_acl.attr_arn
                                      )

 ######################### CICD PIPELINE: #########################

        # Source Stage by GitHub:
        # "Remember to chage the parameter's value in cdk.json for 'owner', 'repo', 'branch', 'action_name', 'oauth_token', and 'secret_id' ":

        # Create source and build input/output artifact.
        source_output = codepipeline.Artifact()
        build_output = codepipeline.Artifact()
        pipeline = codepipeline.Pipeline(self,
                                         f"{env_type.region}-code-pipeline",
                                         cross_account_keys=False,
                                         pipeline_name=f"{env_type.region}-code-pipeline",
                                         )

        pipeline.add_stage(
            stage_name=f"{env_type.region}-Pipeline", actions=[codepipeline_actions.GitHubSourceAction(owner=github_owner.region,  # This is the GitHub username.
                                                                                                       repo=github_repo_name.region,
                                                                                                       # Repo where the app will source its code.
                                                                                                       branch=github_branch_name.region,
                                                                                                       action_name=f"{env_type.region}-pipeline-source",
                                                                                                       oauth_token=cdk.SecretValue.secrets_manager(
                                                                                                           secret_id=secrets_manager_github_token.region),
                                                                                                       output=source_output
                                                                                                       )])

        # # CodeBuild Stage:

        pipeline.add_stage(stage_name=f"{env_type.region}-pipeline-build",
                           actions=[codepipeline_actions.CodeBuildAction(action_name=f"{env_type.region}-pipeline-build",
                                                                         input=source_output,
                                                                         outputs=[
                                                                             build_output],
                                                                         project=codebuild.PipelineProject(
                                                                             self, f"{env_type.region}-Build-Project",
                                                                             environment=codebuild.BuildEnvironment(
                                                                                 compute_type=codebuild.ComputeType.LARGE,
                                                                                 build_image=codebuild.LinuxBuildImage.from_code_build_image_id(
                                                                                     id="aws/codebuild/standard:6.0")
                                                                             ),
                                                                             build_spec=codebuild.BuildSpec.from_source_filename(
                                                                                 filename='buildspec/buildspec.yml'),
                                                                         )
                                                                         )])

# ######################### CFN OUTPUTS: #########################
        """ RDS Proxy Endpoints """

        rds_proxy_writer_endpoint = cdk.CfnOutput(self, f"{env_type.region}-rds-proxy-writer-reader-endpoint",
                                                  value=proxy.endpoint,
                                                  export_name="rds-proxy-writer-endpoint",
                                                  description="RDS Proxy Writer and Reader Endpoint")

        rds_proxy_readonly_endpoint = cdk.CfnOutput(self, f"{env_type.region}-rds-proxy-readonly-endpoint",
                                                    value=read_only_proxy_endpoint.get_att(
                                                        attribute_name="Endpoint").to_string(),
                                                    export_name="rds-proxy-readonly-endpoint",
                                                    description="RDS Proxy ReadOnly Endpoint")

        """ Elasticache Cluster Enpoints: """

        elasticache_configuration_endpoint = cdk.CfnOutput(self, f"{env_type.region}-configuration-endpoint",
                                                           value=cfn_cache_cluster.get_att(
                                                               attribute_name="ConfigurationEndpoint.Address").to_string(),
                                                           export_name="elasticache-configuration-endpoint",
                                                           description="Elasticache Memcached Configuration Endpoint")

        """ Output of the ALB Domain Name """

        alb_dns_name = cdk.CfnOutput(self,
                                     f"{env_type.region}-albDomainName",
                                     value=f"http://{alb.load_balancer_dns_name}",
                                     export_name="alb-dns-name",
                                     description="Web Server ALB Domain Name")

        """ Output of the Cloudfront Domain Name for CNAME Record """
        cloudfront_dns_name = cdk.CfnOutput(self,
                                            f"{env_type.region}-CDN-Domain-Name",
                                            value=cdn.distribution_domain_name,
                                            description="Web Server ALB Domain Name",
                                            export_name="cloudfront-dns-name")


# ######################### TAGGING POLICY: #########################

        cdk.Tags.of(self.vpc).add("ENV", f"{env_type.region}")
        cdk.Tags.of(cfn_transit_gateway_attachment).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.gny_website_asg_sg).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.gny_website_rds_proxy_sg).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.gny_website_rds_elasticache_sg).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.gny_website_efs_sg).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.kms_rds).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.kms_ec2).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.kms_efs).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.rds_subnet_group).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(proxy).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(read_only_proxy_endpoint).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.elasticache_subnet_group).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(alb).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(cdn).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.web_acl).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(web_server_role).add(
            "ENV", f"{env_type.region}")
        cdk.Tags.of(self.db_mysql).add("ENV", f"{env_type.region}")
        cdk.Tags.of(proxy).add("ENV", f"{env_type.region}")
        cdk.Tags.of(cfn_cache_cluster).add("ENV", f"{env_type.region}")
        cdk.Tags.of(self.file_system).add("ENV", f"{env_type.region}")
        cdk.Tags.of(alb).add("ENV", f"{env_type.region}")
        cdk.Tags.of(web_server_asg).add("ENV", f"{env_type.region}")
        cdk.Tags.of(machine_image).add("ENV", f"{env_type.region}")


# 1: Create CICD Pipeline.
# 2: Create AWS Backup.
# 3: Add VPC FlowLogs.
