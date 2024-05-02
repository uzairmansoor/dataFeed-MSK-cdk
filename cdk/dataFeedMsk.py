from constructs import Construct
from aws_cdk import (
    Stack,
    CfnOutput,
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
    aws_kinesisanalytics_flink_alpha as flink,
    Aws as AWS
)
from . import parameters

class dataFeedMsk(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

#############       VPC Configurations      #############

        availabilityZonesList = [parameters.az1, parameters.az2]
        vpc = ec2.Vpc (self, "vpc",
            vpc_name = f"{parameters.project}-{parameters.env}-{parameters.app}-vpc",
            ip_addresses = ec2.IpAddresses.cidr(parameters.cidrRange),
            enable_dns_hostnames = parameters.enableDnsHostnames,
            enable_dns_support = parameters.enableDnsSupport,
            availability_zones = availabilityZonesList,
            nat_gateways = parameters.numberOfNatGateways,
            subnet_configuration = [
                {
                    "name": f"{parameters.project}-{parameters.env}-{parameters.app}-publicSubnet1",
                    "subnetType": ec2.SubnetType.PUBLIC,
                    "cidrMask": parameters.cidrMaskForSubnets,
                },
                {
                    "name": f"{parameters.project}-{parameters.env}-{parameters.app}-privateSubnet1",
                    "subnetType": ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    "cidrMask": parameters.cidrMaskForSubnets,
                }
            ]
        )
        tags.of(vpc).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-vpc")
        tags.of(vpc).add("project", parameters.project)
        tags.of(vpc).add("env", parameters.env)
        tags.of(vpc).add("app", parameters.app)

#############       EC2 Key Pair Configurations      #############

        keyPair = ec2.KeyPair.from_key_pair_name(self, "ec2KeyPair", parameters.keyPairName)

#############       Security Group Configurations      #############

        sgEc2MskCluster = ec2.SecurityGroup(self, "sgEc2MskCluster",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgEc2MskCluster",
            vpc=vpc,
            description="Security group associated with the EC2 instance of MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgEc2MskCluster).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-sgEc2MskCluster")
        tags.of(sgEc2MskCluster).add("project", parameters.project)
        tags.of(sgEc2MskCluster).add("env", parameters.env)
        tags.of(sgEc2MskCluster).add("app", parameters.app)

        sgKafkaProducer = ec2.SecurityGroup(self, "sgKafkaProducer",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgKafkaProducer",
            vpc=vpc,
            description="Security group associated with the Lambda Function",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgKafkaProducer).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-sgKafkaProducer")
        tags.of(sgKafkaProducer).add("project", parameters.project)
        tags.of(sgKafkaProducer).add("env", parameters.env)
        tags.of(sgKafkaProducer).add("app", parameters.app)

        sgMskCluster = ec2.SecurityGroup(self, "sgMskCluster",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgMskCluster",
            vpc=vpc,
            description="Security group associated with the MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgMskCluster).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-sgMskCluster")
        tags.of(sgMskCluster).add("project", parameters.project)
        tags.of(sgMskCluster).add("env", parameters.env)
        tags.of(sgMskCluster).add("app", parameters.app)

        sgApacheFlink = ec2.SecurityGroup(self, "sgApacheFlink",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgApacheFlink",
            vpc=vpc,
            description="Security group associated with the Apache Flink",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgApacheFlink).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-sgApacheFlink")
        tags.of(sgApacheFlink).add("project", parameters.project)
        tags.of(sgApacheFlink).add("env", parameters.env)
        tags.of(sgApacheFlink).add("app", parameters.app)

        sgEc2MskCluster.add_ingress_rule(
            peer = ec2.Peer.any_ipv4(), 
            connection = ec2.Port.tcp(22), 
            description = "Allow SSH access from the internet"
        )

        sgEc2MskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgKafkaInboundPort, parameters.sgKafkaOutboundPort),
            description = "Allow Custom TCP traffic from sgEc2MskCluster to sgMskCluster"
        )

        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgEc2MskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from sgEc2MskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from sgMskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgKafkaProducer.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgKafkaInboundPort, parameters.sgKafkaOutboundPort),
            description = "Allow TCP traffic on port range (9092 - 9098) from security group sgKafkaProducer to security group sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgKafkaProducer.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgKafkaInboundPort, parameters.sgKafkaOutboundPort),
            description = "Allow TCP traffic on port range (9092 - 9098) from security group sgKafkaProducer to security group sgMskCluster"
        )
        sgKafkaProducer.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgKafkaInboundPort, parameters.sgKafkaOutboundPort),
            description = "Allow TCP traffic on port range (9092 - 9098) from security group sgMskCluster to security group sgKafkaProducer"
        )
        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgApacheFlink.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from security group sgApacheFlink to security group sgMskCluster"
        )
        sgApacheFlink.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from security group sgMskCluster to security group sgApacheFlink"
        )
#############       S3 Bucket Configurations      #############

        bucket = s3.Bucket.from_bucket_name(self, "s3BucketAwsBlogArtifacts", parameters.s3BucketName)

#############       KMS Configurations      #############

        customerManagedKey = kms.Key(self, "customerManagedKey",
            alias = f"{parameters.project}-{parameters.env}-{parameters.app}-sasl/scram-key",
            description = "Customer managed key",
            enable_key_rotation = True
            # removal_policy = logs.RemovalPolicy.DESTROY
        )
        tags.of(customerManagedKey).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-customerManagedKey")
        tags.of(customerManagedKey).add("project", parameters.project)
        tags.of(customerManagedKey).add("env", parameters.env)
        tags.of(customerManagedKey).add("app", parameters.app)

#############       Secrets Manager Configurations      #############

        mskClusterSecrets = secretsmanager.Secret(self, "mskClusterSecrets",
            description = "Secrets for MSK Cluster",
            secret_name = f"AmazonMSK_/-{parameters.project}-{parameters.env}-{parameters.app}-secret",
            generate_secret_string = secretsmanager.SecretStringGenerator(
                generate_string_key = "password",
                secret_string_template = '{"username": "%s"}' % parameters.mskClusterUsername,
                exclude_punctuation = True
            ),
            encryption_key=customerManagedKey
        )
        mskClusterPasswordSecretValue = mskClusterSecrets.secret_value_from_json("password").unsafe_unwrap()

        openSearchSecrets = secretsmanager.Secret(self, "openSearchSecrets",
            description = "Secrets for OpenSearch",
            secret_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecrets",
            generate_secret_string = secretsmanager.SecretStringGenerator(),
            encryption_key = customerManagedKey
        )
        openSearchMasterPasswordSecretValue = openSearchSecrets.secret_value
        # openSearchMasterPasswordSecretValueStr = openSearchMasterPasswordSecretValue.to_string()
        openSearchMasterPassword = openSearchMasterPasswordSecretValue.unsafe_unwrap()

#############       SSM Parameter Store Configurations      #############

        mskClusterPwdParamStore = ssm.StringParameter(self, "mskClusterPwdParamStore",
            parameter_name = f"blogAws-{parameters.env}-mskClusterPwd-ssmParamStore",
            string_value = mskClusterPasswordSecretValue,
            tier = ssm.ParameterTier.STANDARD
        )
        mskClusterPwdParamStoreValue = mskClusterPwdParamStore.string_value

#############       Logs of MSK and Apache flink Configurations      #############
        
        mskClusterLogGroup = logs.LogGroup(self, "mskClusterLogGroup",
            log_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterLogGroup",
            retention = logs.RetentionDays.ONE_WEEK
            # removal_policy = logs.LogGroup.apply_removal_policy(RemovalPolicy.DESTROY)
        )
        # mskClusterLogGroup.apply_removal_policy(RemovalPolicy.DESTROY)

        flinkAppLogGroup = logs.LogGroup(self, "apacheFlinkAppLogGroup",
            log_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-flinkAppLogGroup",
            retention = logs.RetentionDays.ONE_WEEK
            # removal_policy = logs.LogGroup.apply_removal_policy(RemovalPolicy.DESTROY)
        )

#############       MSK Cluster Configurations      #############

        mskCluster = msk.CfnCluster(self, "mskCluster",
            cluster_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskCluster",
            kafka_version = parameters.mskVersion,
            number_of_broker_nodes = parameters.mskNumberOfBrokerNodes,
            broker_node_group_info = msk.CfnCluster.BrokerNodeGroupInfoProperty(
                instance_type = parameters.mskClusterInstanceType,
                client_subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
                security_groups = [sgMskCluster.security_group_id],
                connectivity_info=None,
                storage_info = msk.CfnCluster.StorageInfoProperty(  
                    ebs_storage_info = msk.CfnCluster.EBSStorageInfoProperty(
                        volume_size = parameters.mskClusterVolumeSize
                    )
                )
            ),
            logging_info = msk.CfnCluster.LoggingInfoProperty(
                broker_logs = msk.CfnCluster.BrokerLogsProperty(
                    cloud_watch_logs = msk.CfnCluster.CloudWatchLogsProperty(
                        enabled = True,
                        log_group = mskClusterLogGroup.log_group_name
                    ),
                )
            ),
            client_authentication = msk.CfnCluster.ClientAuthenticationProperty(
                sasl = msk.CfnCluster.SaslProperty(
                    scram = msk.CfnCluster.ScramProperty(
                        enabled = parameters.mskScramPropertyEnable
                    )
                )
            ),
            configuration_info=None,
            encryption_info = msk.CfnCluster.EncryptionInfoProperty(
                encryption_in_transit = msk.CfnCluster.EncryptionInTransitProperty(
                    client_broker = parameters.mskEncryptionClientBroker,
                    in_cluster = parameters.mskEncryptionInClusterEnable
                )
            )
        )
        tags.of(mskCluster).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-mskCluster")
        tags.of(mskCluster).add("project", parameters.project)
        tags.of(mskCluster).add("env", parameters.env)
        tags.of(mskCluster).add("app", parameters.app)

        batchScramSecret = msk.CfnBatchScramSecret(self, "mskBatchScramSecret",
            cluster_arn = mskCluster.attr_arn,
            secret_arn_list = [mskClusterSecrets.secret_arn]
        )

        mskClusterArnParamStore = ssm.StringParameter(self, "mskClusterArnParamStore",
            parameter_name = f"blogAws-{parameters.env}-mskClusterArn-ssmParamStore",
            string_value = mskCluster.attr_arn,
            tier = ssm.ParameterTier.STANDARD
        )
        mskClusterArnParamStoreValue = mskClusterArnParamStore.string_value

        mskClusterBrokerUrlParamStore = ssm.StringParameter(self, "mskClusterBrokerUrlParamStore",
            parameter_name = f"blogAws-{parameters.env}-mskClusterBrokerUrl-ssmParamStore",
            string_value = "dummy",
            tier = ssm.ParameterTier.STANDARD
        )

#############       IAM Roles and Policies Configurations      #############

        ec2MskClusterRole = iam.Role(self, "ec2MskClusterRole",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-ec2MskClusterRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        tags.of(ec2MskClusterRole).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-ec2MskClusterRole")
        tags.of(ec2MskClusterRole).add("project", parameters.project)
        tags.of(ec2MskClusterRole).add("env", parameters.env)
        tags.of(ec2MskClusterRole).add("app", parameters.app)
        
        ec2MskClusterRole.attach_inline_policy(
            iam.Policy(self, 'ec2MskClusterPolicy',
                statements = [
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "kafka:ListClusters",
                            "kafka:DescribeCluster",
                            "kafka:DescribeClusterV2",
                            "kafka-cluster:Connect",
                            "kafka-cluster:AlterCluster",
                            "kafka-cluster:DescribeClusterDynamicConfiguration",
                            "kafka-cluster:CreateTopic",
                            "kafka-cluster:DeleteTopic",
                            "kafka-cluster:WriteData",
                            "kafka-cluster:ReadData",
                            "kafka-cluster:AlterGroup",
                            "kafka-cluster:DescribeGroup",
                            "kafka:GetBootstrapBrokers"
                        ],
                        resources= [mskCluster.attr_arn,
                            f"arn:aws:kafka:{AWS.REGION}:{AWS.ACCOUNT_ID}:topic/{mskCluster.cluster_name}/*/*",
                            f"arn:aws:kafka:{AWS.REGION}:{AWS.ACCOUNT_ID}:group/{mskCluster.cluster_name}/*/*"
                        ]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "ec2:DescribeInstances",
                            "ec2:DescribeInstanceAttribute",
                            "ec2:ModifyInstanceAttribute",
                            "ec2:DescribeVpcs",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeTags"
                        ],
                        resources= [f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:instance/*",
                            f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:volume/*",
                            f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:security-group/*"
                        ]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "kafka:GetBootstrapBrokers"
                        ],
                        resources= ["*"]
                    ),
                     iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        resources= [f"arn:aws:logs:{AWS.REGION}:{AWS.ACCOUNT_ID}:log-group:okok:log-stream:*",
                            f"arn:aws:logs:{AWS.REGION}:{AWS.ACCOUNT_ID}:log-group:*"
                        ]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "s3:GetObject",
                            "s3:PutObject"
                        ],
                        resources= [f"arn:aws:s3:::{parameters.sourceBucketName}",
                                    f"arn:aws:s3:::{parameters.sourceBucketName}/*"
                        ]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "ssm:PutParameter",
                            "ssm:GetParameters",
                            "ssm:GetParameter"
                        ],
                        resources= [f"arn:aws:ssm:{AWS.REGION}:{AWS.ACCOUNT_ID}:parameter/{mskClusterBrokerUrlParamStore.parameter_name}"]
                    )
                ]
            )
        )

        apacheFlinkAppRole = iam.Role(self, "apacheFlinkAppRole",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkAppRole",
            assumed_by=iam.ServicePrincipal("kinesisanalytics.amazonaws.com"),
            managed_policies = [
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonMSKReadOnlyAccess")
            ]
        )
        tags.of(ec2MskClusterRole).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkAppRole")
        tags.of(ec2MskClusterRole).add("project", parameters.project)
        tags.of(ec2MskClusterRole).add("env", parameters.env)
        tags.of(ec2MskClusterRole).add("app", parameters.app)

        apacheFlinkAppRole.attach_inline_policy(
            iam.Policy(self, 'apacheFlinkAppPolicy',
                statements = [
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions = [
                            "s3:GetObject",
                            "s3:GetObjectVersion"
                        ],
                        resources = [f"{bucket.bucket_arn}/{parameters.apacheFlinkBucketKey}"]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions = [
                            "logs:DescribeLogGroups"
                        ],
                        resources = [flinkAppLogGroup.log_group_arn]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions = [
                            "ec2:DescribeVpcs",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeDhcpOptions"
                        ],
                        resources = ["*"]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions = [
                            "ec2:CreateNetworkInterface",
                            # "ec2:CreateNetworkInterfacePermission",
                            "ec2:DescribeNetworkInterfaces",
                            "ec2:DeleteNetworkInterface"
                        ],
                        resources = [f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:network-interface/*",
                                     f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:security-group/*",
                                     f"arn:aws:ec2:{AWS.REGION}:{AWS.ACCOUNT_ID}:subnet/*"
                        ]
                    )
                ]
            )
        )

#############       MSK Client and Producer EC2 Instance Configurations      #############

        kafkaClientEc2BlockDevices = ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(10))
        kafkaClientEC2Instance = ec2.Instance(self, "kafkaClientEC2Instance",
            instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaClientEC2Instance",
            vpc = vpc,
            instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters.ec2InstanceClass), ec2.InstanceSize(parameters.ec2InstanceSize)),
            machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.ec2AmiName),
            availability_zone = vpc.availability_zones[1],
            block_devices = [kafkaClientEc2BlockDevices],
            vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            key_pair = keyPair,
            security_group = sgEc2MskCluster,
            user_data = ec2.UserData.for_linux(),
            role = ec2MskClusterRole
        )

        kafkaClientEC2Instance.user_data.add_commands(
            "sudo su",
            "sudo yum update -y",
            "sudo yum -y install java-11",
            "sudo yum install jq -y",
            "wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz",
            "tar -xzf kafka_2.13-3.5.1.tgz",
            "cd kafka_2.13-3.5.1/libs",
            "wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar",
            "cd /home/ec2-user",
            "cat <<EOF > /home/ec2-user/users_jaas.conf",
            "KafkaClient {",
            f"    org.apache.kafka.common.security.scram.ScramLoginModule required",
            f'    username="{parameters.mskClusterUsername}"',
            f'    password="{mskClusterPwdParamStoreValue}";',
            "};",
            "EOF",
            "export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
            f"export BOOTSTRAP_SERVERS=$(aws kafka get-bootstrap-brokers --cluster-arn {mskCluster.attr_arn} --region {AWS.REGION} | jq -r \'.BootstrapBrokerStringSaslScram\')",
            f'aws ssm put-parameter --name {mskClusterBrokerUrlParamStore.parameter_name} --value "$BOOTSTRAP_SERVERS" --type "{mskClusterBrokerUrlParamStore.parameter_type}" --overwrite --region {AWS.REGION}',
            "mkdir tmp",
            "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
            "cat <<EOF > /home/ec2-user/client_sasl.properties",
            f"security.protocol=SASL_SSL",
            f"sasl.mechanism=SCRAM-SHA-512",
            f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
            "EOF",
            f'/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters.mskTopicName1} --replication-factor 2',
            f'/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters.mskTopicName2} --replication-factor 2',
            f'/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --list --command-config ./client_sasl.properties',  
            "cd /home/ec2-user",
            "sudo yum update -y",
            "sudo yum install python3 -y",
            "sudo yum install python3-pip -y",
            "sudo mkdir environment",
            "cd environment",
            "sudo yum install python3 virtualenv -y",
            "sudo pip3 install virtualenv",
            "sudo python3 -m virtualenv alpaca-script",
            "source alpaca-script/bin/activate",
            f"pip install -r <(aws s3 cp s3://{parameters.sourceBucketName}/python-scripts/requirement.txt -)",
            f"aws s3 cp s3://{parameters.sourceBucketName}/python-scripts/ec2-script-historic.py .",
            f"aws s3 cp s3://{parameters.sourceBucketName}/python-scripts/stock_mapper.py .",
            f"aws s3 cp s3://{parameters.sourceBucketName}/python-scripts/ec2-script-live.py .",
            'export API_KEY=PKPBAXYRYGBBDNGOBYV9',
            'export SECRET_KEY=FC4vp8HUkno88tttRMYpONbOBTmcY9lcFXqc5msa',
            'export KAFKA_SASL_MECHANISM=SCRAM-SHA-512',
            f'export KAFKA_SASL_USERNAME={parameters.mskClusterUsername}',
            f'export KAFKA_SASL_PASSWORD={mskClusterPwdParamStoreValue}',
            "python3 ec2-script-historic.py"
        )

#############       Overriding some properties of MSK cluster      #############

        mskClusterConfigProperties = [
            "auto.create.topics.enable=false",
            "default.replication.factor=3",
            "min.insync.replicas=2",
            "num.io.threads=8",
            "num.network.threads=5",
            "num.partitions=1",
            "num.replica.fetchers=2",
            "replica.lag.time.max.ms=30000",
            "socket.receive.buffer.bytes=102400",
            "socket.request.max.bytes=104857600",
            "socket.send.buffer.bytes=102400",
            "unclean.leader.election.enable=false",
            "zookeeper.session.timeout.ms=18000"
        ]
#allow.everyone.if.no.acl.found=false
        mskClusterConfigProperties = "\n".join(mskClusterConfigProperties)
        mskClusterConfiguration = msk.CfnConfiguration(self, "mskClusterConfiguration",
            name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterConfiguration",
            server_properties = mskClusterConfigProperties,
            description = "MSK cluster configuration"
        )

        # mskCluster.add_property_override(
        #     'BrokerNodeGroupInfo.ConnectivityInfo',
        #     {
        #         'VpcConnectivity': {
        #             'ClientAuthentication': {
        #                 'Sasl': {
        #                     'Iam': {'Enabled': False},
        #                     'Scram': {'Enabled': True}
        #                 },
        #                 'Tls': {'Enabled': False}
        #             }
        #         }
        #     }
        # )

        # mskCluster.add_property_override(
        #     'ConfigurationInfo',
        #     {
        #         "arn": mskClusterConfiguration.attr_arn,
        #         "revision": mskClusterConfiguration.attr_latest_revision_revision
        #     }
        # )

#################################################### 2nd Cluster Thing Start ####################################################
        # kafkaClientEc2BlockDevices2 = ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(10))
        # kafkaClientEC2Instance2 = ec2.Instance(self, "kafkaClientEC2Instance2",
        #     instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaClientEC2Instance2",
        #     vpc = vpc,
        #     instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters.ec2InstanceClass), ec2.InstanceSize(parameters.ec2InstanceSize)),
        #     machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.ec2AmiName),
        #     availability_zone = vpc.availability_zones[1],
        #     block_devices = [kafkaClientEc2BlockDevices2],
        #     vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        #     key_pair = keyPair,
        #     security_group = sgEc2MskCluster,
        #     user_data = ec2.UserData.for_linux(),
        #     role = ec2MskClusterRole
        # )

        # kafkaClientEC2Instance2.user_data.add_commands(
        #     "sudo su",
        #     "sudo yum update -y",
        #     "sudo yum -y install java-11",
        #     "sudo yum install jq -y",
        #     "wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz",
        #     "tar -xzf kafka_2.13-3.5.1.tgz",
        #     "cd kafka_2.13-3.5.1/libs",
        #     "wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar",
        #     "cd /home/ec2-user",
        #     "cat <<EOF > /home/ec2-user/users_jaas.conf",
        #     "KafkaClient {",
        #     f"    org.apache.kafka.common.security.scram.ScramLoginModule required",
        #     f'    username="{parameters.mskClusterUsername}"',
        #     f'    password="{mskClusterPwdParamStoreValue}";',
        #     "};",
        #     "EOF",
        #     "export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
        #     f"broker_url=$(aws kafka get-bootstrap-brokers --cluster-arn {mskCluster2.attr_arn} --region {AWS.REGION}| jq -r '.BootstrapBrokerStringSaslScram')",
        #     "mkdir tmp",
        #     "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
        #     "cat <<EOF > /home/ec2-user/client_sasl.properties",
        #     f"security.protocol=SASL_SSL",
        #     f"sasl.mechanism=SCRAM-SHA-512",
        #     f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
        #     "EOF",
        #     f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server \"$broker_url\" --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters.mskTopicName1} --replication-factor 2",
        #     f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server \"$broker_url\" --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters.mskTopicName2} --replication-factor 2",

        #     "cd /home/ec2-user",
        #     "sudo yum update -y",
        #     "sudo yum install python3 -y",
        #     "sudo yum install python3-pip -y",
        #     "sudo mkdir environment",
        #     "cd environment",
        #     "sudo yum install python3 virtualenv -y",
        #     "sudo pip3 install virtualenv",
        #     "sudo python3 -m virtualenv alpaca-script",
        #     "source alpaca-script/bin/activate",
        #     f"pip install -r <(aws s3 cp s3://{parameters.sourceBucketName}/python-scripts/requirement.txt -)",
        #     f"aws s3 cp s3://{parameters.sourceBucketName}/python-scripts/ec2-script-historic.py .",
        #     f"aws s3 cp s3://{parameters.sourceBucketName}/python-scripts/stock_mapper.py .",
        #     "export API_KEY=PKPBAXYRYGBBDNGOBYV9",
        #     "export SECRET_KEY=FC4vp8HUkno88tttRMYpONbOBTmcY9lcFXqc5msa",
        #     "export export BOOTSTRAP_SERVERS={bootstrap-server-endpoint}",
        #     "export KAFKA_SASL_MECHANISM=SCRAM-SHA-512",
        #     f'"export KAFKA_SASL_USERNAME="{parameters.mskClusterUsername}""',
        #     f'"export KAFKA_SASL_PASSWORD="{mskClusterPwdParamStoreValue}""',
        #     "python3 ec2-script-historic.py"
        # )
        
        # mskCluster2 = msk.CfnCluster(
        #     self, "mskCluster2",
        #     cluster_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskCluster2",
        #     kafka_version = parameters.mskVersion,
        #     number_of_broker_nodes = parameters.mskNumberOfBrokerNodes,
        #     broker_node_group_info = msk.CfnCluster.BrokerNodeGroupInfoProperty(
        #         instance_type = parameters.mskClusterInstanceType,
        #         client_subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
        #         security_groups = [sgMskCluster.security_group_id],
        #         storage_info = msk.CfnCluster.StorageInfoProperty(  
        #             ebs_storage_info = msk.CfnCluster.EBSStorageInfoProperty(
        #                 volume_size = parameters.mskClusterVolumeSize
        #             )
        #         ),
        #         connectivity_info = msk.CfnCluster.ConnectivityInfoProperty(
        #             vpc_connectivity=msk.CfnCluster.VpcConnectivityProperty(
        #                 client_authentication=msk.CfnCluster.VpcConnectivityClientAuthenticationProperty(
        #                     sasl=msk.CfnCluster.VpcConnectivitySaslProperty(
        #                         iam=msk.CfnCluster.VpcConnectivityIamProperty(
        #                             enabled=False
        #                         ),
        #                         scram=msk.CfnCluster.VpcConnectivityScramProperty(
        #                             enabled=True
        #                         )
        #                     ),
        #                     tls=msk.CfnCluster.VpcConnectivityTlsProperty(
        #                         enabled=False
        #                     )
        #                 )
        #             )
        #         )
        #     ),
        #     client_authentication = msk.CfnCluster.ClientAuthenticationProperty(
        #         sasl = msk.CfnCluster.SaslProperty(
        #             scram = msk.CfnCluster.ScramProperty(
        #                 enabled = parameters.mskScramPropertyEnable
        #             )
        #         )
        #     ),
        #     configuration_info={
        #         "arn": mskClusterConfiguration.attr_arn,
        #         "revision": mskClusterConfiguration.attr_latest_revision_revision
        #     },
        #     encryption_info = msk.CfnCluster.EncryptionInfoProperty(
        #         encryption_in_transit = msk.CfnCluster.EncryptionInTransitProperty(
        #             client_broker = parameters.mskEncryptionClientBroker,
        #             in_cluster = parameters.mskEncryptionInClusterEnable
        #         )
        #     )
        # )
        # tags.of(mskCluster2).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-mskCluster2")
        # tags.of(mskCluster2).add("project", parameters.project)
        # tags.of(mskCluster2).add("env", parameters.env)
        # tags.of(mskCluster2).add("app", parameters.app)

        # batchScramSecret2 = msk.CfnBatchScramSecret(self, "mskBatchScramSecret",
        #     cluster_arn = mskCluster2.attr_arn,
        #     secret_arn_list = [mskClusterSecrets.secret_arn]
        # )

        # mskCluster2.add_property_override(
        #     'BrokerNodeGroupInfo.ConnectivityInfo',
        #     {
        #         'VpcConnectivity': {
        #             'ClientAuthentication': {
        #                 'Sasl': {
        #                     'Iam': {'Enabled': False},
        #                     'Scram': {'Enabled': True}
        #                 },
        #                 'Tls': {'Enabled': False}
        #             }
        #         }
        #     }
        # )
#################################################### 2nd Cluster Thing End ####################################################

        # mskClusterVpcConnection = msk.CfnVpcConnection(self, "mskClusterVpcConnection",
        #     authentication="SASL_SCRAM",
        #     client_subnets=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
        #     security_groups=[sgMskCluster.security_group_id],
        #     target_cluster_arn=mskCluster.attr_arn,
        #     vpc_id=vpc.vpc_id
        # )
        # tags.of(mskClusterVpcConnection).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterVpcConnection")
        # tags.of(mskClusterVpcConnection).add("project", parameters.project)
        # tags.of(mskClusterVpcConnection).add("env", parameters.env)
        # tags.of(mskClusterVpcConnection).add("app", parameters.app)
        # mskClusterVpcConnection.node.add_dependency(mskCluster)
        
        # mskClusterPolicy = msk.CfnClusterPolicy(self, "mskClusterPolicy",
        #     cluster_arn=mskClusterArnParamStoreValue,
        #     policy={
        #         "Version": "2012-10-17",
        #         "Statement": [
        #             {
        #                 "Effect": "Allow",
        #                 "Principal": {
        #                     "AWS": [parameters.mskCrossAccountId]
        #                 },
        #                 "Action": [
        #                     "kafka:CreateVpcConnection",
        #                     "kafka:GetBootstrapBrokers",
        #                     "kafka:DescribeCluster",
        #                     "kafka:DescribeClusterV2"
        #                 ],
        #                 "Resource": mskClusterArnParamStoreValue
        #             }
        #         ]
        #     }
        # )
        # mskClusterPolicy.node.add_dependency(mskCluster)

#############       OpenSearch Configurations      #############

        opensearch_access_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            actions=["es:*"],
            resources= ["*"]#[f"{openSearchDomain.domain_arn}/*"]
        )

        OPENSEARCH_VERSION = parameters.openSearchVersion
        openSearchDomain = opensearch.Domain(self, "openSearchDomain",
            domain_name = f"awsblog-{parameters.env}-public-domain",
            version = opensearch.EngineVersion.open_search(OPENSEARCH_VERSION),
            capacity = opensearch.CapacityConfig(
                multi_az_with_standby_enabled = parameters.openSearchMultiAzWithStandByEnable,
                # master_nodes = parameters.openSearchMasterNodes,
                # master_node_instance_type = parameters.masterNodeInstanceType,
                data_nodes = parameters.openSearchDataNodes,
                data_node_instance_type = parameters.openSearchDataNodeInstanceType
            ),
            ebs = opensearch.EbsOptions(
                volume_size = parameters.openSearchVolumeSize,
                volume_type = ec2.EbsDeviceVolumeType.GP3
            ),
            access_policies = [opensearch_access_policy],
            enforce_https = True,                                                 # Required when FGAC is enabled
            node_to_node_encryption = parameters.openSearchNodeToNodeEncryption,  # Required when FGAC is enabled
            encryption_at_rest = opensearch.EncryptionAtRestOptions(
                enabled = parameters.openSearchEncryptionAtRest
            ),
            fine_grained_access_control = opensearch.AdvancedSecurityOptions(
                master_user_name = parameters.openSearchMasterUsername,
                master_user_password = openSearchMasterPasswordSecretValue
            )
        )
        # openSearchDomainEndpoint = openSearchDomain.domain_endpoint

#############       Apache Flink Configurations      #############

        # FLINK_RUNTIME_VERSION = parameters.apacheFlinkRuntimeVersion
        sgApacheFlinkId = ec2.SecurityGroup.from_security_group_id(self, "sgApacheFlinkId", security_group_id = sgApacheFlink.security_group_id)
        apacheFlinkApp = flink.Application(self, "apacheFlinkApp",
            code = flink.ApplicationCode.from_bucket(bucket = bucket,file_key = parameters.apacheFlinkBucketKey),
            runtime = flink.Runtime.FLINK_1_18,
            application_name = f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkApp",
            vpc = vpc,
            security_groups = [sgApacheFlinkId],
            vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            auto_scaling_enabled = parameters.apacheFlinkAutoScalingEnable,
            property_groups = {
                "FlinkApplicationProperties": {
                    "msk.username" : parameters.mskClusterUsername,
                    "msk.broker.url" : mskClusterBrokerUrlParamStore.string_value,
                    "msk.password" : mskClusterPasswordSecretValue, 
                    "opensearch.endpoint" : openSearchDomain.domain_endpoint,
                    "opensearch.username" : parameters.openSearchMasterUsername,
                    "opensearch.password" : openSearchMasterPassword, #openSearchMasterPasswordSecretValueStr,
                    "opensearch.port" : "443",
                    "event.ticker.interval.minutes" : parameters.eventTickerIntervalMinutes,
                    "event.ticker.1" : parameters.mskTopicName1,
                    "event.ticker.2" : parameters.mskTopicName2
                }
            },
            role = apacheFlinkAppRole,
            parallelism = parameters.apacheFlinkParallelism,
            parallelism_per_kpu = parameters.apacheFlinkParallelismPerKpu,
            checkpointing_enabled = parameters.apacheFlinkCheckpointingEnabled,
            log_group = flinkAppLogGroup
        )
        tags.of(ec2MskClusterRole).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkApp")
        tags.of(ec2MskClusterRole).add("project", parameters.project)
        tags.of(ec2MskClusterRole).add("env", parameters.env)
        tags.of(ec2MskClusterRole).add("app", parameters.app)

#############       Output Values      #############

        CfnOutput(self, "vpcId",
            value = vpc.vpc_id,
            description = "VPC Id",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-vpcId"
        )
        CfnOutput(self, "sgEc2MskClusterId",
            value=sgEc2MskCluster.security_group_id,
            description = "Security group Id of EC2 MSK cluster",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgEc2MskClusterId"
        )
        CfnOutput(self, "sgKafkaProducerId",
            value=sgKafkaProducer.security_group_id,
            description = "Security group Id of EC2 kafka producer",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgKafkaProducerId"
        )
        CfnOutput(self, "sgMskClusterId",
            value=sgMskCluster.security_group_id,
            description = "Security group Id of MSK Cluster",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgMskClusterId"
        )
        CfnOutput(self, "ec2MskClusterRoleArn",
            value=ec2MskClusterRole.role_arn,
            description = "ARN of EC2 MSK cluster role",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-ec2MskClusterRoleArn"
        )
        CfnOutput(self, "mskClusterName",
            value=mskCluster.cluster_name,
            description = "Name of an MSK cluster",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterName"
        )
        CfnOutput(self, "mskClusterArn",
            value=mskCluster.attr_arn,
            description = "ARN of an MSK cluster",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterArn"
        )
        CfnOutput(self, "apacheFlinkAppRoleArn",
            value=apacheFlinkAppRole.role_arn,
            description = "ARN of apache flink app role",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkAppRoleArn"
        )
        # CfnOutput(self, "kafkaProducerEC2InstanceId",
        #     value=kafkaProducerEC2Instance.instance_id,
        #     description = "Kafka producer EC2 instance Id",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaProducerEC2InstanceId"
        # )
        # CfnOutput(self, "kafkaClientEC2InstanceId",
        #     value=kafkaClientEC2Instance.instance_id,
        #     description = "Kafka client EC2 instance Id",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaClientEC2InstanceId"
        # )
        CfnOutput(self, "customerManagedKeyArn",
            value=customerManagedKey.key_arn,
            description = "ARN of customer managed key",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-customerManagedKeyArn"
        )
        CfnOutput(self, "mskClusterSecretsArn",
            value=mskClusterSecrets.secret_arn,
            description = "ARN of MSK cluster secrets",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterSecretsArn"
        )
        CfnOutput(self, "mskClusterSecretsName",
            value=mskClusterSecrets.secret_name,
            description = "MSK cluster secrets name",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterSecretsName"
        )
        CfnOutput(self, "flinkAppLogGroupArn",
            value = flinkAppLogGroup.log_group_arn,
            description = "Arn of an Apache Flink log group",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-flinkAppLogGroupArn"
        )
        CfnOutput(self, "flinkAppLogGroupName",
            value = flinkAppLogGroup.log_group_name,
            description = "Name of an Apache Flink log group",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-flinkAppLogGroupName"
        )
        CfnOutput(self, "apacheFlinkAppArn",
            value = apacheFlinkApp.application_arn,
            description = "Arn of an Apache Flink application",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkAppArn"
        )
        CfnOutput(self, "apacheFlinkAppName",
            value = apacheFlinkApp.application_name,
            description = "Name of an Apache Flink application",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkAppName"
        )
        CfnOutput(self, "openSearchSecretsArn",
            value=openSearchSecrets.secret_arn,
            description = "ARN of MSK cluster secrets",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecretsArn"
        )
        CfnOutput(self, "openSearchDomainName",
            value=openSearchDomain.domain_name,
            description = "OpenSearch domain name",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchDomainName"
        )
        CfnOutput(self, "openSearchDomainEndpoint",
            value=openSearchDomain.domain_endpoint,
            description = "OpenSearch domain endpoint",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchDomainEndpoint"
        )