from constructs import Construct
from aws_cdk import (
    Stack,
    CfnOutput,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_s3 as s3,
    aws_msk as msk,
    aws_ssm as ssm,
    aws_secretsmanager as secretsmanager,
    aws_opensearchservice as opensearch,
    aws_kms as kms,
    aws_logs as logs,
    Tags as tags,
    aws_opensearchservice as opensearch,
    aws_kinesisanalyticsv2 as kinesisanalyticsv2,
    Aws as AWS,
    aws_msk_alpha as mskAlpha
)
from . import parameters_copy_dump

class dataFeedMsk(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

#############       VPC Configurations      #############

        availabilityZonesList = [parameters_copy_dump.az1, parameters_copy_dump.az2]
        vpc = ec2.Vpc (self, "vpc",
            vpc_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-vpc",
            ip_addresses = ec2.IpAddresses.cidr(parameters_copy_dump.cidrRange),
            enable_dns_hostnames = parameters_copy_dump.enableDnsHostnames,
            enable_dns_support = parameters_copy_dump.enableDnsSupport,
            availability_zones = availabilityZonesList,
            nat_gateways = parameters_copy_dump.numberOfNatGateways,
            subnet_configuration = [
                {
                    "name": f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-public",
                    "subnetType": ec2.SubnetType.PUBLIC,
                    "cidrMask": parameters_copy_dump.cidrMaskForSubnets,
                },
                {
                    "name": f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-private",
                    "subnetType": ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    "cidrMask": parameters_copy_dump.cidrMaskForSubnets,
                }
            ]
        )
        tags.of(vpc).add("name", f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-vpc")
        tags.of(vpc).add("project", parameters_copy_dump.project)
        tags.of(vpc).add("env", parameters_copy_dump.env)
        tags.of(vpc).add("app", parameters_copy_dump.app)

#############       EC2 Key Pair Configurations      #############

        keyPair = ec2.KeyPair.from_key_pair_name(self, "ec2KeyPair", parameters_copy_dump.keyPairName)

#############       Security Group Configurations      #############

        sgEc2MskCluster = ec2.SecurityGroup(self, "sgEc2MskCluster",
            security_group_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgEc2MskCluster",
            vpc=vpc,
            description="Security group associated with the EC2 instance of MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgEc2MskCluster).add("name", f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgEc2MskCluster")
        tags.of(sgEc2MskCluster).add("project", parameters_copy_dump.project)
        tags.of(sgEc2MskCluster).add("env", parameters_copy_dump.env)
        tags.of(sgEc2MskCluster).add("app", parameters_copy_dump.app)

        sgMskCluster = ec2.SecurityGroup(self, "sgMskCluster",
            security_group_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgMskCluster",
            vpc=vpc,
            description="Security group associated with the MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgMskCluster).add("name", f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgMskCluster")
        tags.of(sgMskCluster).add("project", parameters_copy_dump.project)
        tags.of(sgMskCluster).add("env", parameters_copy_dump.env)
        tags.of(sgMskCluster).add("app", parameters_copy_dump.app)

        sgApacheFlink = ec2.SecurityGroup(self, "sgApacheFlink",
            security_group_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgApacheFlink",
            vpc=vpc,
            description="Security group associated with the Apache Flink",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgApacheFlink).add("name", f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgApacheFlink")
        tags.of(sgApacheFlink).add("project", parameters_copy_dump.project)
        tags.of(sgApacheFlink).add("env", parameters_copy_dump.env)
        tags.of(sgApacheFlink).add("app", parameters_copy_dump.app)

        sgEc2MskCluster.add_ingress_rule(
            peer = ec2.Peer.any_ipv4(), 
            connection = ec2.Port.tcp(22), 
            description = "Allow SSH access from the internet"
        )

        sgEc2MskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters_copy_dump.sgKafkaInboundPort, parameters_copy_dump.sgKafkaOutboundPort),
            description = "Allow Custom TCP traffic from sgEc2MskCluster to sgMskCluster"
        )

        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgEc2MskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters_copy_dump.sgMskClusterInboundPort, parameters_copy_dump.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from sgEc2MskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters_copy_dump.sgMskClusterInboundPort, parameters_copy_dump.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from sgMskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgApacheFlink.security_group_id),
            connection = ec2.Port.tcp_range(parameters_copy_dump.sgMskClusterInboundPort, parameters_copy_dump.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from security group sgApacheFlink to security group sgMskCluster"
        )
        sgApacheFlink.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters_copy_dump.sgMskClusterInboundPort, parameters_copy_dump.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from security group sgMskCluster to security group sgApacheFlink"
        )
#############       S3 Bucket Configurations      #############

        bucket = s3.Bucket.from_bucket_name(self, "s3BucketAwsBlogArtifacts", parameters_copy_dump.s3BucketName)

#############       KMS Configurations      #############

        customerManagedKey = kms.Key(self, "customerManagedKey",
            alias = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sasl/scram-key",
            description = "Customer managed key",
            enable_key_rotation = True,
            removal_policy = RemovalPolicy.DESTROY
        )
        tags.of(customerManagedKey).add("name", f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-customerManagedKey")
        tags.of(customerManagedKey).add("project", parameters_copy_dump.project)
        tags.of(customerManagedKey).add("env", parameters_copy_dump.env)
        tags.of(customerManagedKey).add("app", parameters_copy_dump.app)

#############       Secrets Manager Configurations      #############

        mskClusterSecrets = secretsmanager.Secret(self, "mskClusterSecrets",
            description = "Secrets for MSK Cluster",
            secret_name = f"AmazonMSK_/-{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-secret",
            generate_secret_string = secretsmanager.SecretStringGenerator(
                generate_string_key = "password",
                secret_string_template = '{"username": "%s"}' % parameters_copy_dump.mskClusterUsername,
                exclude_punctuation = True
            ),
            encryption_key=customerManagedKey
        )
        mskClusterPasswordSecretValue = mskClusterSecrets.secret_value_from_json("password").unsafe_unwrap()

        openSearchSecrets = secretsmanager.Secret(self, "openSearchSecrets",
            description = "Secrets for OpenSearch",
            secret_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-openSearchSecrets",
            generate_secret_string = secretsmanager.SecretStringGenerator(),
            encryption_key = customerManagedKey
        )
        openSearchMasterPasswordSecretValue = openSearchSecrets.secret_value
        openSearchMasterPassword = openSearchMasterPasswordSecretValue.unsafe_unwrap()

#############       SSM Parameter Store Configurations      #############

        mskClusterPwdParamStore = ssm.StringParameter(self, "mskClusterPwdParamStore",
            parameter_name = f"blogAws-{parameters_copy_dump.env}-mskClusterPwd-ssmParamStore",
            string_value = mskClusterPasswordSecretValue,
            tier = ssm.ParameterTier.STANDARD
        )
        mskClusterPwdParamStoreValue = mskClusterPwdParamStore.string_value

#############       Logs of MSK and Apache flink Configurations      #############
        
        mskClusterLogGroup = logs.LogGroup(self, "mskClusterLogGroup",
            log_group_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-mskClusterLogGroup",
            retention = logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        apacheFlinkAppLogGroup = logs.LogGroup(self, "apacheFlinkAppLogGroup",
            log_group_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-flinkAppLogGroup",
            retention = logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )
        
        apacheFlinkAppLogStream = logs.LogStream(self, "apacheFlinkAppLogStream",
            log_stream_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-flinkAppLogStream",
            log_group = logs.LogGroup.from_log_group_name(self, "importLogGroupName", log_group_name = apacheFlinkAppLogGroup.log_group_name),
            removal_policy = RemovalPolicy.DESTROY
        )

#############       MSK Cluster Configurations      #############

        mskAlphaCluster = mskAlpha.Cluster(self, "mskAlphaCluster",
            cluster_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-mskAlphaCluster",
            kafka_version = mskAlpha.KafkaVersion.V3_5_1,
            instance_type = ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
            vpc=vpc,
            vpc_subnets = ec2.SubnetSelection(subnets = vpc.private_subnets),
            security_groups = [ec2.SecurityGroup.from_security_group_id(self, "importSecurityGroup", security_group_id = sgMskCluster.security_group_id)],
            ebs_storage_info = mskAlpha.EbsStorageInfo(
                volume_size = parameters_copy_dump.mskClusterVolumeSize
            ),
            number_of_broker_nodes = parameters_copy_dump.mskNumberOfBrokerNodes,
            encryption_in_transit = mskAlpha.EncryptionInTransitConfig(
                client_broker = mskAlpha.ClientBrokerEncryption.TLS,
                enable_in_cluster = True
            ),
            client_authentication=mskAlpha.ClientAuthentication.sasl(
                scram=True
            ),
            configuration_info = None,
            logging = mskAlpha.BrokerLogging(
                cloudwatch_log_group = logs.LogGroup.from_log_group_name(self, "importLogGroup", log_group_name = mskClusterLogGroup.log_group_name)
            )
        )
        
        self.msk_cluster_arn = mskAlphaCluster.cluster_arn
        # mskAlpha.ClusterConfigurationInfo

        # mskCluster = msk.CfnCluster(self, "mskCluster",
        #     cluster_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-mskCluster",
        #     kafka_version = parameters_copy.mskVersion,
        #     number_of_broker_nodes = parameters_copy.mskNumberOfBrokerNodes,
        #     broker_node_group_info = msk.CfnCluster.BrokerNodeGroupInfoProperty(
        #         instance_type = parameters_copy.mskClusterInstanceType,
        #         client_subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
        #         security_groups = [sgMskCluster.security_group_id],
        #         connectivity_info=None,
        #         storage_info = msk.CfnCluster.StorageInfoProperty(  
        #             ebs_storage_info = msk.CfnCluster.EBSStorageInfoProperty(
        #                 volume_size = parameters_copy.mskClusterVolumeSize
        #             )
        #         )
        #     ),
        #     logging_info = msk.CfnCluster.LoggingInfoProperty(
        #         broker_logs = msk.CfnCluster.BrokerLogsProperty(
        #             cloud_watch_logs = msk.CfnCluster.CloudWatchLogsProperty(
        #                 enabled = True,
        #                 log_group = mskClusterLogGroup.log_group_name
        #             ),
        #         )
        #     ),
        #     client_authentication = msk.CfnCluster.ClientAuthenticationProperty(
        #         sasl = msk.CfnCluster.SaslProperty(
        #             scram = msk.CfnCluster.ScramProperty(
        #                 enabled = parameters_copy.mskScramPropertyEnable
        #             )
        #         )
        #     ),
        #     configuration_info=None,
        #     encryption_info = msk.CfnCluster.EncryptionInfoProperty(
        #         encryption_in_transit = msk.CfnCluster.EncryptionInTransitProperty(
        #             client_broker = parameters_copy.mskEncryptionClientBroker,
        #             in_cluster = parameters_copy.mskEncryptionInClusterEnable
        #         )
        #     )
        # )
        # tags.of(mskCluster).add("name", f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-mskCluster")
        # tags.of(mskCluster).add("project", parameters_copy.project)
        # tags.of(mskCluster).add("env", parameters_copy.env)
        # tags.of(mskCluster).add("app", parameters_copy.app)

        # batchScramSecret = msk.CfnBatchScramSecret(self, "mskBatchScramSecret",
        #     cluster_arn = mskCluster.attr_arn,
        #     secret_arn_list = [mskClusterSecrets.secret_arn]
        # )

        mskClusterArnParamStore = ssm.StringParameter(self, "mskClusterArnParamStore",
            parameter_name = f"blogAws-{parameters_copy_dump.env}-mskClusterArn-ssmParamStore",
            string_value = mskAlphaCluster.cluster_arn,
            tier = ssm.ParameterTier.STANDARD
        )
        mskClusterArnParamStoreValue = mskClusterArnParamStore.string_value

        mskClusterBrokerUrlParamStore = ssm.StringParameter(self, "mskClusterBrokerUrlParamStore",
            parameter_name = f"blogAws-{parameters_copy_dump.env}-mskClusterBrokerUrl-ssmParamStore",
            string_value = "dummy",         # We're passing a dummy value in this SSM parameter. The actual value will be replaced by EC2 userdata during the process
            tier = ssm.ParameterTier.STANDARD
        )

#############       IAM Roles and Policies Configurations      #############

        # ec2MskClusterRole = iam.Role(self, "ec2MskClusterRole",
        #     role_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-ec2MskClusterRole",
        #     assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        # )
        # tags.of(ec2MskClusterRole).add("name", f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-ec2MskClusterRole")
        # tags.of(ec2MskClusterRole).add("project", parameters_copy.project)
        # tags.of(ec2MskClusterRole).add("env", parameters_copy.env)
        # tags.of(ec2MskClusterRole).add("app", parameters_copy.app)
        
        # ec2MskClusterRole.attach_inline_policy(
        #     iam.Policy(self, 'ec2MskClusterPolicy',
        #         statements = [
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions=[
        #                     "kafka:ListClusters",
        #                     "kafka:DescribeCluster",
        #                     "kafka-cluster:Connect",
        #                     "kafka-cluster:ReadData",
        #                     "kafka:DescribeClusterV2",
        #                     "kafka-cluster:CreateTopic",
        #                     "kafka-cluster:DeleteTopic",
        #                     "kafka-cluster:AlterCluster",
        #                     "kafka-cluster:WriteData",
        #                     "kafka-cluster:AlterGroup",
        #                     "kafka-cluster:DescribeGroup",
        #                     "kafka:GetBootstrapBrokers",
        #                     "kafka-cluster:DescribeClusterDynamicConfiguration",
        #                 ],
        #                 resources= [mskCluster.attr_arn,
        #                     f"arn:aws:kafka:{AWS.REGION}:{AWS.ACCOUNT_ID}:topic/{mskCluster.cluster_name}/*/*",
        #                     f"arn:aws:kafka:{AWS.REGION}:{AWS.ACCOUNT_ID}:group/{mskCluster.cluster_name}/*/*"
        #                 ]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions=[
        #                     "ec2:DescribeInstances",
        #                     "ec2:DescribeInstanceAttribute",
        #                     "ec2:ModifyInstanceAttribute",
        #                     "ec2:DescribeVpcs",
        #                     "ec2:DescribeSecurityGroups",
        #                     "ec2:DescribeSubnets",
        #                     "ec2:DescribeTags"
        #                 ],
        #                 resources= [f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:instance/*",
        #                     f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:volume/*",
        #                     f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:security-group/*"
        #                 ]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions=[
        #                     "kafka:GetBootstrapBrokers"
        #                 ],
        #                 resources= ["*"]
        #             ),
        #              iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions=[
        #                     "logs:CreateLogGroup",
        #                     "logs:CreateLogStream",
        #                     "logs:PutLogEvents",
        #                 ],
        #                 resources= [f"arn:aws:logs:{AWS.REGION}:{AWS.ACCOUNT_ID}:log-group:okok:log-stream:*",
        #                     f"arn:aws:logs:{AWS.REGION}:{AWS.ACCOUNT_ID}:log-group:*"
        #                 ]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions=[
        #                     "s3:GetObject",
        #                     "s3:PutObject"
        #                 ],
        #                 resources= [f"arn:aws:s3:::{parameters_copy.sourceBucketName}",
        #                             f"arn:aws:s3:::{parameters_copy.sourceBucketName}/*"
        #                 ]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions=[
        #                     "ssm:PutParameter",
        #                     "ssm:Getparameters",
        #                     "ssm:GetParameter"
        #                 ],
        #                 resources= [f"arn:aws:ssm:{AWS.REGION}:{AWS.ACCOUNT_ID}:parameter/{mskClusterBrokerUrlParamStore.parameter_name}"]
        #             )
        #         ]
        #     )
        # )

        # apacheFlinkAppRole = iam.Role(self, "apacheFlinkAppRole",
        #     role_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-apacheFlinkAppRole",
        #     assumed_by=iam.ServicePrincipal("kinesisanalytics.amazonaws.com"),
        #     managed_policies = [
        #         iam.ManagedPolicy.from_aws_managed_policy_name("AmazonMSKReadOnlyAccess")
        #     ]
        # )
        # tags.of(apacheFlinkAppRole).add("name", f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-apacheFlinkAppRole")
        # tags.of(apacheFlinkAppRole).add("project", parameters_copy.project)
        # tags.of(apacheFlinkAppRole).add("env", parameters_copy.env)
        # tags.of(apacheFlinkAppRole).add("app", parameters_copy.app)

        # apacheFlinkAppRole.attach_inline_policy(
        #     iam.Policy(self, 'apacheFlinkAppPolicy',
        #         statements = [
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions = [
        #                     "s3:GetObject",
        #                     "s3:GetObjectVersion"
        #                 ],
        #                 resources = [f"{bucket.bucket_arn}/{parameters_copy.apacheFlinkBucketKey}"]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions = [
        #                     "logs:DescribeLogGroups"
        #                 ],
        #                 resources = [apacheFlinkAppLogGroup.log_group_arn]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions = [
        #                     "ec2:DescribeVpcs",
        #                     "ec2:DescribeSubnets",
        #                     "ec2:DescribeSecurityGroups",
        #                     "ec2:DescribeDhcpOptions"
        #                 ],
        #                 resources = ["*"]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions = [
        #                     "ec2:CreateNetworkInterface",
        #                     "ec2:CreateNetworkInterfacePermission",
        #                     "ec2:DescribeNetworkInterfaces",
        #                     "ec2:DeleteNetworkInterface"
        #                 ],
        #                 resources = [f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:network-interface/*",
        #                              f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:security-group/*",
        #                              f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:subnet/*"
        #                 ]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions = [
        #                     "logs:DescribeLogStreams"
        #                 ],
        #                 resources = [f"arn:aws:logs:{AWS.REGION}:{AWS.ACCOUNT_ID}:log-group:{apacheFlinkAppLogGroup.log_group_name}:log-stream:*"]
        #             ),
        #             iam.PolicyStatement(
        #                 effect = iam.Effect.ALLOW,
        #                 actions = [
        #                     "logs:PutLogEvents"
        #                 ],
        #                 resources = [f"arn:aws:logs:{AWS.REGION}:{AWS.ACCOUNT_ID}:log-group:{apacheFlinkAppLogGroup.log_group_name}:log-stream:{apacheFlinkAppLogStream.log_stream_name}"
        #                 ]
        #             )
        #         ]
        #     )
        # )

# #############       MSK Client and Producer EC2 Instance Configurations      #############

#         kafkaClientEc2BlockDevices = ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(10))
#         kafkaClientEC2Instance = ec2.Instance(self, "kafkaClientEC2Instance",
#             instance_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-kafkaClientEC2Instance",
#             vpc = vpc,
#             instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters_copy.ec2InstanceClass), ec2.InstanceSize(parameters_copy.ec2InstanceSize)),
#             machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters_copy.ec2AmiName),
#             availability_zone = vpc.availability_zones[1],
#             block_devices = [kafkaClientEc2BlockDevices],
#             vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
#             key_pair = keyPair,
#             security_group = sgEc2MskCluster,
#             user_data = ec2.UserData.for_linux(),
#             role = ec2MskClusterRole
#         )

#         kafkaClientEC2Instance.user_data.add_commands(
#             "sudo su",
#             "sudo yum update -y",
#             "sudo yum -y install java-11",
#             "sudo yum install jq -y",
#             "wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz",
#             "tar -xzf kafka_2.13-3.5.1.tgz",
#             "cd kafka_2.13-3.5.1/libs",
#             "wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar",
#             "cd /home/ec2-user",
#             "cat <<EOF > /home/ec2-user/users_jaas.conf",
#             "KafkaClient {",
#             f"    org.apache.kafka.common.security.scram.ScramLoginModule required",
#             f'    username="{parameters_copy.mskClusterUsername}"',
#             f'    password="{mskClusterPwdParamStoreValue}";',
#             "};",
#             "EOF",
#             "export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
#             f"export BOOTSTRAP_SERVERS=$(aws kafka get-bootstrap-brokers --cluster-arn {mskCluster.attr_arn} --region {AWS.REGION} | jq -r \'.BootstrapBrokerStringSaslScram\')",
#             f'aws ssm put-parameter --name {mskClusterBrokerUrlParamStore.parameter_name} --value "$BOOTSTRAP_SERVERS" --type "{mskClusterBrokerUrlParamStore.parameter_type}" --overwrite --region {AWS.REGION}',
#             "mkdir tmp",
#             "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
#             "cat <<EOF > /home/ec2-user/client_sasl.properties",
#             f"security.protocol=SASL_SSL",
#             f"sasl.mechanism=SCRAM-SHA-512",
#             f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
#             "EOF",
#             f'/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters_copy.mskTopicName1} --replication-factor 2',
#             f'/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters_copy.mskTopicName2} --replication-factor 2',
#             f'/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --list --command-config ./client_sasl.properties',  
#             "cd /home/ec2-user",
#             "sudo yum update -y",
#             "sudo yum install python3 -y",
#             "sudo yum install python3-pip -y",
#             "sudo mkdir environment",
#             "cd environment",
#             "sudo yum install python3 virtualenv -y",
#             "sudo pip3 install virtualenv",
#             "sudo python3 -m virtualenv alpaca-script",
#             "source alpaca-script/bin/activate",
#             f"pip install -r <(aws s3 cp s3://{parameters_copy.sourceBucketName}/python-scripts/requirement.txt -)",
#             f"aws s3 cp s3://{parameters_copy.sourceBucketName}/python-scripts/ec2-script-historic-para.py .",
#             f"aws s3 cp s3://{parameters_copy.sourceBucketName}/python-scripts/stock_mapper.py .",
#             f"aws s3 cp s3://{parameters_copy.sourceBucketName}/python-scripts/ec2-script-live.py .",
#             'export API_KEY=PKECLY5H0GVN02PAODUC',
#             'export SECRET_KEY=AFHK20nUtVfmiTfuMTUV51OJe4YaQybUSbAs7o02',
#             'export KAFKA_SASL_MECHANISM=SCRAM-SHA-512',
#             f'export KAFKA_SASL_USERNAME={parameters_copy.mskClusterUsername}',
#             f'export KAFKA_SASL_PASSWORD={mskClusterPwdParamStoreValue}',
#             "python3 ec2-script-historic-para.py"
#         )

# #############       Overriding some properties of MSK cluster      #############

#         mskClusterConfigProperties = [
#             "auto.create.topics.enable=false",
#             "default.replication.factor=3",
#             "min.insync.replicas=2",
#             "num.io.threads=8",
#             "num.network.threads=5",
#             "num.partitions=1",
#             "num.replica.fetchers=2",
#             "replica.lag.time.max.ms=30000",
#             "socket.receive.buffer.bytes=102400",
#             "socket.request.max.bytes=104857600",
#             "socket.send.buffer.bytes=102400",
#             "unclean.leader.election.enable=false",
#             "zookeeper.session.timeout.ms=18000"
#         ]
# #allow.everyone.if.no.acl.found=false
#         mskClusterConfigProperties = "\n".join(mskClusterConfigProperties)
#         mskClusterConfiguration = msk.CfnConfiguration(self, "mskClusterConfiguration",
#             name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-mskClusterConfiguration",
#             server_properties = mskClusterConfigProperties,
#             description = "MSK cluster configuration"
#         )

# #############       2nd Iteration      #############

#         # mskCluster.add_property_override(
#         #     'BrokerNodeGroupInfo.ConnectivityInfo',
#         #     {
#         #         'VpcConnectivity': {
#         #             'ClientAuthentication': {
#         #                 'Sasl': {
#         #                     'Iam': {'Enabled': False},
#         #                     'Scram': {'Enabled': True}
#         #                 },
#         #                 'Tls': {'Enabled': False}
#         #             }
#         #         }
#         #     }
#         # )

#         # mskCluster.add_property_override(
#         #     'ConfigurationInfo',
#         #     {
#         #         "arn": mskClusterConfiguration.attr_arn,
#         #         "revision": mskClusterConfiguration.attr_latest_revision_revision
#         #     }
#         # )

# #################################################### 2nd Cluster Thing Start ####################################################
#         # kafkaClientEc2BlockDevices2 = ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(10))
#         # kafkaClientEC2Instance2 = ec2.Instance(self, "kafkaClientEC2Instance2",
#         #     instance_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-kafkaClientEC2Instance2",
#         #     vpc = vpc,
#         #     instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters_copy.ec2InstanceClass), ec2.InstanceSize(parameters_copy.ec2InstanceSize)),
#         #     machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters_copy.ec2AmiName),
#         #     availability_zone = vpc.availability_zones[1],
#         #     block_devices = [kafkaClientEc2BlockDevices2],
#         #     vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
#         #     key_pair = keyPair,
#         #     security_group = sgEc2MskCluster,
#         #     user_data = ec2.UserData.for_linux(),
#         #     role = ec2MskClusterRole
#         # )

#         # kafkaClientEC2Instance2.user_data.add_commands(
#         #     "sudo su",
#         #     "sudo yum update -y",
#         #     "sudo yum -y install java-11",
#         #     "sudo yum install jq -y",
#         #     "wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz",
#         #     "tar -xzf kafka_2.13-3.5.1.tgz",
#         #     "cd kafka_2.13-3.5.1/libs",
#         #     "wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar",
#         #     "cd /home/ec2-user",
#         #     "cat <<EOF > /home/ec2-user/users_jaas.conf",
#         #     "KafkaClient {",
#         #     f"    org.apache.kafka.common.security.scram.ScramLoginModule required",
#         #     f'    username="{parameters_copy.mskClusterUsername}"',
#         #     f'    password="{mskClusterPwdParamStoreValue}";',
#         #     "};",
#         #     "EOF",
#         #     "export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
#         #     f"broker_url=$(aws kafka get-bootstrap-brokers --cluster-arn {mskCluster2.attr_arn} --region {AWS.REGION}| jq -r '.BootstrapBrokerStringSaslScram')",
#         #     "mkdir tmp",
#         #     "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
#         #     "cat <<EOF > /home/ec2-user/client_sasl.properties",
#         #     f"security.protocol=SASL_SSL",
#         #     f"sasl.mechanism=SCRAM-SHA-512",
#         #     f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
#         #     "EOF",
#         #     f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server \"$broker_url\" --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters_copy.mskTopicName1} --replication-factor 2",
#         #     f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server \"$broker_url\" --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters_copy.mskTopicName2} --replication-factor 2",

#         #     "cd /home/ec2-user",
#         #     "sudo yum update -y",
#         #     "sudo yum install python3 -y",
#         #     "sudo yum install python3-pip -y",
#         #     "sudo mkdir environment",
#         #     "cd environment",
#         #     "sudo yum install python3 virtualenv -y",
#         #     "sudo pip3 install virtualenv",
#         #     "sudo python3 -m virtualenv alpaca-script",
#         #     "source alpaca-script/bin/activate",
#         #     f"pip install -r <(aws s3 cp s3://{parameters_copy.sourceBucketName}/python-scripts/requirement.txt -)",
#         #     f"aws s3 cp s3://{parameters_copy.sourceBucketName}/python-scripts/ec2-script-historic.py .",
#         #     f"aws s3 cp s3://{parameters_copy.sourceBucketName}/python-scripts/stock_mapper.py .",
#         #     "export API_KEY=PKPBAXYRYGBBDNGOBYV9",
#         #     "export SECRET_KEY=FC4vp8HUkno88tttRMYpONbOBTmcY9lcFXqc5msa",
#         #     "export export BOOTSTRAP_SERVERS={bootstrap-server-endpoint}",
#         #     "export KAFKA_SASL_MECHANISM=SCRAM-SHA-512",
#         #     f'"export KAFKA_SASL_USERNAME="{parameters_copy.mskClusterUsername}""',
#         #     f'"export KAFKA_SASL_PASSWORD="{mskClusterPwdParamStoreValue}""',
#         #     "python3 ec2-script-historic.py"
#         # )
        
#         # cluster = msk.Cluster(self, 'Cluster',
#         #     cluster_name = 'myCluster',
#         #     kafka_version = parameters_copy.mskVersion,
#         #     vpc = ec2.Vpc.from_vpc_attributes(self, "importedVpc",
#         #         availability_zones = "us-east-1a",
#         #         vpc_id = vpc.vpc_id    
#         #     )
#         # )

#         # mskCluster2 = msk.CfnCluster(
#         #     self, "mskCluster2",
#         #     cluster_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-mskCluster2",
#         #     kafka_version = parameters_copy.mskVersion,
#         #     number_of_broker_nodes = parameters_copy.mskNumberOfBrokerNodes,
#         #     broker_node_group_info = msk.CfnCluster.BrokerNodeGroupInfoProperty(
#         #         instance_type = parameters_copy.mskClusterInstanceType,
#         #         client_subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
#         #         security_groups = [sgMskCluster.security_group_id],
#         #         storage_info = msk.CfnCluster.StorageInfoProperty(  
#         #             ebs_storage_info = msk.CfnCluster.EBSStorageInfoProperty(
#         #                 volume_size = parameters_copy.mskClusterVolumeSize
#         #             )
#         #         ),
#         #         connectivity_info = msk.CfnCluster.ConnectivityInfoProperty(
#         #             vpc_connectivity=msk.CfnCluster.VpcConnectivityProperty(
#         #                 client_authentication=msk.CfnCluster.VpcConnectivityClientAuthenticationProperty(
#         #                     sasl=msk.CfnCluster.VpcConnectivitySaslProperty(
#         #                         iam=msk.CfnCluster.VpcConnectivityIamProperty(
#         #                             enabled=False
#         #                         ),
#         #                         scram=msk.CfnCluster.VpcConnectivityScramProperty(
#         #                             enabled=True
#         #                         )
#         #                     ),
#         #                     tls=msk.CfnCluster.VpcConnectivityTlsProperty(
#         #                         enabled=False
#         #                     )
#         #                 )
#         #             )
#         #         )
#         #     ),
#         #     client_authentication = msk.CfnCluster.ClientAuthenticationProperty(
#         #         sasl = msk.CfnCluster.SaslProperty(
#         #             scram = msk.CfnCluster.ScramProperty(
#         #                 enabled = parameters_copy.mskScramPropertyEnable
#         #             )
#         #         )
#         #     ),
#         #     configuration_info={
#         #         "arn": mskClusterConfiguration.attr_arn,
#         #         "revision": mskClusterConfiguration.attr_latest_revision_revision
#         #     },
#         #     encryption_info = msk.CfnCluster.EncryptionInfoProperty(
#         #         encryption_in_transit = msk.CfnCluster.EncryptionInTransitProperty(
#         #             client_broker = parameters_copy.mskEncryptionClientBroker,
#         #             in_cluster = parameters_copy.mskEncryptionInClusterEnable
#         #         )
#         #     )
#         # )
#         # tags.of(mskCluster2).add("name", f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-mskCluster2")
#         # tags.of(mskCluster2).add("project", parameters_copy.project)
#         # tags.of(mskCluster2).add("env", parameters_copy.env)
#         # tags.of(mskCluster2).add("app", parameters_copy.app)

#         # batchScramSecret2 = msk.CfnBatchScramSecret(self, "mskBatchScramSecret",
#         #     cluster_arn = mskCluster2.attr_arn,
#         #     secret_arn_list = [mskClusterSecrets.secret_arn]
#         # )

#         # mskCluster2.add_property_override(
#         #     'BrokerNodeGroupInfo.ConnectivityInfo',
#         #     {
#         #         'VpcConnectivity': {
#         #             'ClientAuthentication': {
#         #                 'Sasl': {
#         #                     'Iam': {'Enabled': False},
#         #                     'Scram': {'Enabled': True}
#         #                 },
#         #                 'Tls': {'Enabled': False}
#         #             }
#         #         }
#         #     }
#         # )
# #################################################### 2nd Cluster Thing End ####################################################

#         # mskClusterVpcConnection = msk.CfnVpcConnection(self, "mskClusterVpcConnection",
#         #     authentication="SASL_SCRAM",
#         #     client_subnets=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
#         #     security_groups=[sgMskCluster.security_group_id],
#         #     target_cluster_arn=mskCluster.attr_arn,
#         #     vpc_id=vpc.vpc_id
#         # )
#         # tags.of(mskClusterVpcConnection).add("name", f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-mskClusterVpcConnection")
#         # tags.of(mskClusterVpcConnection).add("project", parameters_copy.project)
#         # tags.of(mskClusterVpcConnection).add("env", parameters_copy.env)
#         # tags.of(mskClusterVpcConnection).add("app", parameters_copy.app)
#         # mskClusterVpcConnection.node.add_dependency(mskCluster)
        
#         # mskClusterPolicy = msk.CfnClusterPolicy(self, "mskClusterPolicy",
#         #     cluster_arn=mskClusterArnParamStoreValue,
#         #     policy={
#         #         "Version": "2012-10-17",
#         #         "Statement": [
#         #             {
#         #                 "Effect": "Allow",
#         #                 "Principal": {
#         #                     "AWS": [parameters_copy.mskCrossAccountId]
#         #                 },
#         #                 "Action": [
#         #                     "kafka:CreateVpcConnection",
#         #                     "kafka:GetBootstrapBrokers",
#         #                     "kafka:DescribeCluster",
#         #                     "kafka:DescribeClusterV2"
#         #                 ],
#         #                 "Resource": mskClusterArnParamStoreValue
#         #             }
#         #         ]
#         #     }
#         # )
#         # mskClusterPolicy.node.add_dependency(mskCluster)

# #############       OpenSearch Configurations      #############

#         opensearch_access_policy = iam.PolicyStatement(
#             effect=iam.Effect.ALLOW,
#             principals=[iam.AnyPrincipal()],
#             actions=["es:*"],
#             resources= ["*"]#[f"{openSearchDomain.domain_arn}/*"]
#         )

#         OPENSEARCH_VERSION = parameters_copy.openSearchVersion
#         openSearchDomain = opensearch.Domain(self, "openSearchDomain",
#             domain_name = f"awsblog-{parameters_copy.env}-public-domain",
#             version = opensearch.EngineVersion.open_search(OPENSEARCH_VERSION),
#             capacity = opensearch.CapacityConfig(
#                 multi_az_with_standby_enabled = parameters_copy.openSearchMultiAzWithStandByEnable,
#                 data_nodes = parameters_copy.openSearchDataNodes,
#                 data_node_instance_type = parameters_copy.openSearchDataNodeInstanceType
#             ),
#             ebs = opensearch.EbsOptions(
#                 volume_size = parameters_copy.openSearchVolumeSize,
#                 volume_type = ec2.EbsDeviceVolumeType.GP3
#             ),
#             access_policies = [opensearch_access_policy],
#             enforce_https = True,                                                 # Required when FGAC is enabled
#             node_to_node_encryption = parameters_copy.openSearchNodeToNodeEncryption,  # Required when FGAC is enabled
#             encryption_at_rest = opensearch.EncryptionAtRestOptions(
#                 enabled = parameters_copy.openSearchEncryptionAtRest
#             ),
#             fine_grained_access_control = opensearch.AdvancedSecurityOptions(
#                 master_user_name = parameters_copy.openSearchMasterUsername,
#                 master_user_password = openSearchMasterPasswordSecretValue
#             )
#         )
#         openSearchDomain.node.add_dependency(kafkaClientEC2Instance)

# #############       Apache Flink Configurations      #############

#         subnetIds = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids
#         apacheFlinkApp = kinesisanalyticsv2.CfnApplication(self, "apacheFlinkApp",
#             application_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-apacheFlinkApp",
#             application_description = "Apache Flink Application",
#             runtime_environment=parameters_copy.apacheFlinkRuntimeVersion,
#             service_execution_role=apacheFlinkAppRole.role_arn,
#             application_configuration=kinesisanalyticsv2.CfnApplication.ApplicationConfigurationProperty(
#                 application_code_configuration=kinesisanalyticsv2.CfnApplication.ApplicationCodeConfigurationProperty(
#                     code_content_type = "ZIPFILE",
#                     code_content=kinesisanalyticsv2.CfnApplication.CodeContentProperty(
#                         s3_content_location=kinesisanalyticsv2.CfnApplication.S3ContentLocationProperty(
#                             bucket_arn=bucket.bucket_arn,
#                             file_key=parameters_copy.apacheFlinkBucketKey,
#                         )
#                     )
#                 ),
#                 application_snapshot_configuration=kinesisanalyticsv2.CfnApplication.ApplicationSnapshotConfigurationProperty(
#                     snapshots_enabled=False
#                 ),
#                 flink_application_configuration=kinesisanalyticsv2.CfnApplication.FlinkApplicationConfigurationProperty(
#                     checkpoint_configuration=kinesisanalyticsv2.CfnApplication.CheckpointConfigurationProperty(
#                         configuration_type="CUSTOM",
#                         checkpointing_enabled=True
#                     ),
#                     monitoring_configuration=kinesisanalyticsv2.CfnApplication.MonitoringConfigurationProperty(
#                         configuration_type="CUSTOM",
#                         log_level="INFO",
#                         metrics_level="APPLICATION"
#                     ),
#                     parallelism_configuration=kinesisanalyticsv2.CfnApplication.ParallelismConfigurationProperty(
#                         configuration_type="CUSTOM",
#                         auto_scaling_enabled=True
#                     )
#                 ),
#                 environment_properties=kinesisanalyticsv2.CfnApplication.EnvironmentPropertiesProperty(
#                     property_groups=[kinesisanalyticsv2.CfnApplication.PropertyGroupProperty(
#                         property_group_id="FlinkApplicationProperties",
#                         property_map={
#                             "msk.username" : parameters_copy.mskClusterUsername,
#                             "msk.broker.url" : mskClusterBrokerUrlParamStore.string_value,
#                             "msk.password" : mskClusterPasswordSecretValue, 
#                             "opensearch.endpoint" : openSearchDomain.domain_endpoint,
#                             "opensearch.username" : parameters_copy.openSearchMasterUsername,
#                             "opensearch.password" : openSearchMasterPassword,
#                             "opensearch.port" : "443",
#                             "event.ticker.interval.minutes" : parameters_copy.eventTickerIntervalMinutes,
#                             "event.ticker.1" : parameters_copy.mskTopicName1,
#                             "event.ticker.2" : parameters_copy.mskTopicName2
#                         }
#                     )]
#                 ),
#                 vpc_configurations = [kinesisanalyticsv2.CfnApplication.VpcConfigurationProperty(
#                     security_group_ids = [sgApacheFlink.security_group_id],
#                     subnet_ids = subnetIds
#                 )],
#             )
#         )
#         apacheFlinkApp.node.add_dependency(apacheFlinkAppRole)
#         apacheFlinkApp.node.add_dependency(sgApacheFlink)
#         apacheFlinkApp.node.add_dependency(kafkaClientEC2Instance)
#         apacheFlinkApp.node.add_dependency(openSearchDomain)
#         tags.of(apacheFlinkApp).add("name", f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-apacheFlinkApp")
#         tags.of(apacheFlinkApp).add("project", parameters_copy.project)
#         tags.of(apacheFlinkApp).add("env", parameters_copy.env)
#         tags.of(apacheFlinkApp).add("app", parameters_copy.app)

#         apacheFlinkAppLogs = kinesisanalyticsv2.CfnApplicationCloudWatchLoggingOption(self, "apacheFlinkAppLogs",
#             application_name = apacheFlinkApp.application_name,
#             cloud_watch_logging_option = kinesisanalyticsv2.CfnApplicationCloudWatchLoggingOption.CloudWatchLoggingOptionProperty(
#                 log_stream_arn = f"arn:aws:logs:{AWS.REGION}:{AWS.ACCOUNT_ID}:log-group:{apacheFlinkAppLogGroup.log_group_name}:log-stream:{apacheFlinkAppLogStream.log_stream_name}"
#             )
#         )
#         apacheFlinkAppLogs.node.add_dependency(apacheFlinkApp)

#############       Output Values      #############

        CfnOutput(self, "vpcId",
            value = vpc.vpc_id,
            description = "VPC Id",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-vpcId"
        )
        CfnOutput(self, "sgEc2MskClusterId",
            value = sgEc2MskCluster.security_group_id,
            description = "Security group Id of EC2 MSK cluster",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgEc2MskClusterId"
        )
        CfnOutput(self, "sgMskClusterId",
            value = sgMskCluster.security_group_id,
            description = "Security group Id of MSK Cluster",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-sgMskClusterId"
        )
        # CfnOutput(self, "ec2MskClusterRoleArn",
        #     value = ec2MskClusterRole.role_arn,
        #     description = "ARN of EC2 MSK cluster role",
        #     export_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-ec2MskClusterRoleArn"
        # )
        CfnOutput(self, "mskClusterName",
            value = mskAlphaCluster.cluster_name,
            description = "Name of an MSK cluster",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-mskClusterName"
        )
        CfnOutput(self, "mskClusterArn",
            value = mskAlphaCluster.cluster_arn,
            description = "ARN of an MSK cluster",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-mskClusterArn"
        )
        # CfnOutput(self, "apacheFlinkAppRoleArn",
        #     value = apacheFlinkAppRole.role_arn,
        #     description = "ARN of apache flink app role",
        #     export_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-apacheFlinkAppRoleArn"
        # )
        # CfnOutput(self, "kafkaProducerEC2InstanceId",
        #     value = kafkaProducerEC2Instance.instance_id,
        #     description = "Kafka producer EC2 instance Id",
        #     export_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-kafkaProducerEC2InstanceId"
        # )
        # CfnOutput(self, "kafkaClientEC2InstanceId",
        #     value = kafkaClientEC2Instance.instance_id,
        #     description = "Kafka client EC2 instance Id",
        #     export_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-kafkaClientEC2InstanceId"
        # )
        CfnOutput(self, "customerManagedKeyArn",
            value = customerManagedKey.key_arn,
            description = "ARN of customer managed key",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-customerManagedKeyArn"
        )
        CfnOutput(self, "mskClusterSecretsArn",
            value = mskClusterSecrets.secret_arn,
            description = "ARN of MSK cluster secrets",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-mskClusterSecretsArn"
        )
        CfnOutput(self, "mskClusterSecretsName",
            value = mskClusterSecrets.secret_name,
            description = "MSK cluster secrets name",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-mskClusterSecretsName"
        )
        CfnOutput(self, "flinkAppLogGroupArn",
            value = apacheFlinkAppLogGroup.log_group_arn,
            description = "Arn of an Apache Flink log group",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-apacheFlinkAppLogGroupArn"
        )
        CfnOutput(self, "flinkAppLogGroupName",
            value = apacheFlinkAppLogGroup.log_group_name,
            description = "Name of an Apache Flink log group",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-apacheFlinkAppLogGroupName"
        )
        CfnOutput(self, "openSearchSecretsArn",
            value = openSearchSecrets.secret_arn,
            description = "ARN of MSK cluster secrets",
            export_name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-openSearchSecretsArn"
        )
        # CfnOutput(self, "openSearchDomainName",
        #     value = openSearchDomain.domain_name,
        #     description = "OpenSearch domain name",
        #     export_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-openSearchDomainName"
        # )
        # CfnOutput(self, "openSearchDomainEndpoint",
        #     value = openSearchDomain.domain_endpoint,
        #     description = "OpenSearch domain endpoint",
        #     export_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-openSearchDomainEndpoint"
        # )
        # CfnOutput(self, "apacheFlinkAppName",
        #     value = apacheFlinkApp.application_name,
        #     description = "Apache flink application name",
        #     export_name = f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-apacheFlinkAppName"
        # )