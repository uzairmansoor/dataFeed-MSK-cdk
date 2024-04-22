from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    CfnOutput,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_sns_subscriptions as subs,
    aws_signer as signer,
    aws_lambda as _lambda,
    aws_s3 as s3,
    aws_iam as iam,
    aws_msk as msk,
    aws_ssm as ssm,
    custom_resources as cr,
    aws_secretsmanager as secretsmanager,
    aws_opensearchservice as opensearch,
    aws_kms as kms,
    aws_logs as logs,
    Tags as tags,
    aws_opensearchservice as opensearch,
    aws_kinesisanalytics_flink_alpha as flink
)
# const accountId = cdk.Aws.ACCOUNT_ID;
# const region = cdk.Aws.REGION;
from . import parameters
import json
import os.path

app_region = os.environ["CDK_DEFAULT_REGION"]

class dataFeedMskAwsBlogStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        availabilityZonesList = [parameters.az1, parameters.az2]
        vpc = ec2.Vpc (self, "vpc",
            ip_addresses = ec2.IpAddresses.cidr(parameters.cidr_range),
            enable_dns_hostnames = parameters.enable_dns_hostnames,
            enable_dns_support = parameters.enable_dns_support,
            availability_zones = availabilityZonesList,
            nat_gateways = parameters.no_of_nat_gateways,
            subnet_configuration = [
                {
                    "name": f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-publicSubnet1",
                    "subnetType": ec2.SubnetType.PUBLIC,
                    "cidrMask": parameters.cidrMaskForSubnets,
                },
                {
                    "name": f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-privateSubnet1",
                    "subnetType": ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    "cidrMask": parameters.cidrMaskForSubnets,
                },
                {
                    "name": f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-isolatedSubnet-1",
                    "subnetType": ec2.SubnetType.PRIVATE_ISOLATED,
                    "cidrMask": parameters.cidrMaskForSubnets,
                },
            ]
        )
        tags.of(vpc).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-vpc")
        tags.of(vpc).add("project", parameters.project)
        tags.of(vpc).add("env", parameters.env)
        tags.of(vpc).add("app", parameters.app)

        keyPair = ec2.KeyPair.from_key_pair_name(self, "ec2KeyPair", parameters.keyPairName)

        sgEc2MskCluster = ec2.SecurityGroup(self, "sgEc2MskCluster",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgEc2MskCluster",
            vpc=vpc,
            description="Security group associated with the EC2 instance of MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        

        sgKafkaProducer = ec2.SecurityGroup(self, "sgKafkaProducer",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgKafkaProducer",
            vpc=vpc,
            description="Security group associated with the Lambda Function",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        

        sgMskCluster = ec2.SecurityGroup(self, "sgMskCluster",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgMskCluster",
            vpc=vpc,
            description="Security group associated with the MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        
        tags.of(sgEc2MskCluster).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-sgEc2MskCluster")
        tags.of(sgEc2MskCluster).add("project", parameters.project)
        tags.of(sgEc2MskCluster).add("env", parameters.env)
        tags.of(sgEc2MskCluster).add("app", parameters.app)

        tags.of(sgKafkaProducer).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-sgKafkaProducer")
        tags.of(sgKafkaProducer).add("project", parameters.project)
        tags.of(sgKafkaProducer).add("env", parameters.env)
        tags.of(sgKafkaProducer).add("app", parameters.app)

        tags.of(sgMskCluster).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-sgMskCluster")
        tags.of(sgMskCluster).add("project", parameters.project)
        tags.of(sgMskCluster).add("env", parameters.env)
        tags.of(sgMskCluster).add("app", parameters.app)

        sgEc2MskCluster.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "Allow SSH access from the internet")

        sgMskCluster.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgEc2MskCluster.security_group_id),
            connection=ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description="Allow all TCP traffic from sgEc2MskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection=ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description="Allow all TCP traffic from sgMskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgKafkaProducer.security_group_id),
            connection=ec2.Port.tcp_range(parameters.sgKafkaInboundPort, parameters.sgKafkaOutboundPort),
            description="Allow TCP traffic on port range (9092 - 9098) from security group sgKafkaProducer to security group sgMskCluster"
        )

        sgKafkaProducer.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection=ec2.Port.tcp_range(parameters.sgKafkaInboundPort, parameters.sgKafkaOutboundPort),
            description="Allow TCP traffic on port range (9092 - 9098) from security group sgMskCluster to security group sgKafkaProducer"
        )

        bucket = s3.Bucket.from_bucket_name(self, "s3BucketAwsBlogArtifacts", parameters.bucket_name)
        
        ec2MskClusterRole = iam.Role(self, "ec2MskClusterRole",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-ec2MskClusterRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        tags.of(ec2MskClusterRole).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-ec2MskClusterRole")
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
                            "kafka:DescribeCluster"
                        ],
                        resources= ["*"] #["arn:aws:kafka:*:*:cluster/*"]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "ec2:DescribeInstances",
                            "ec2:DescribeInstanceAttribute",
                            "ec2:ModifyInstanceAttribute",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeTags",
                            "kafka-cluster:Connect",
                            "kafka-cluster:AlterCluster",
                            "kafka-cluster:DescribeCluster",
                            "kafka-cluster:DescribeClusterDynamicConfiguration",
                            "kafka-cluster:CreateTopic",
                            "kafka-cluster:DeleteTopic",
                            "kafka-cluster:WriteData",
                            "kafka-cluster:ReadData",
                            "kafka-cluster:AlterGroup",
                            "kafka-cluster:DescribeGroup",
                            "kafka:GetBootstrapBrokers"
                        ],
                        resources= ["*"] #["arn:aws:kafka:*:*:cluster/*"]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "s3:*",
                            "s3-object-lambda:*"
                        ],
                        resources= ["*"] #["arn:aws:kafka:*:*:cluster/*"]
                    ),
                ]
            )
        )

        ec2KafkaProducerRole = iam.Role(self, "ec2KafkaProducerRole",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-ec2KafkaProducerRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        tags.of(ec2KafkaProducerRole).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-ec2KafkaProducerRole")
        tags.of(ec2KafkaProducerRole).add("project", parameters.project)
        tags.of(ec2KafkaProducerRole).add("env", parameters.env)
        tags.of(ec2KafkaProducerRole).add("app", parameters.app)

        ec2KafkaProducerRole.attach_inline_policy(
            iam.Policy(self, 'lambdaFunctionExecutionPolicy',
                statements = [
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "kafka:DescribeCluster",
                            "kafka:DescribeClusterV2",
                            "kafka:GetBootstrapBrokers",
                            "ec2:CreateNetworkInterface",
                            "ec2:DescribeNetworkInterfaces",
                            "ec2:DescribeVpcs",
                            "ec2:DeleteNetworkInterface",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeSecurityGroups",
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        resources= ["*"] #["arn:aws:kafka:*:*:cluster/*"]
                    ),
                    iam.PolicyStatement(
                        effect = iam.Effect.ALLOW,
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "ec2:CreateNetworkInterface",
                            "ec2:DescribeNetworkInterfaces",
                            "ec2:DescribeSubnets",
                            "ec2:DeleteNetworkInterface",
                            "ec2:AssignPrivateIpAddresses",
                            "ec2:UnassignPrivateIpAddresses"
                        ],
                        resources= ["*"] #["arn:aws:kafka:*:*:topic/*/*"]
                    )
                ]
            )
        )

        kafkaProducerEc2BlockDevices = ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(10))
        kafkaProducerEC2Instance = ec2.Instance(self, "kafkaProducerEC2Instance",
            instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaProducerEC2Instance",
            vpc = vpc,
            instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters.instanceClass), ec2.InstanceSize(parameters.instanceSize)),
            machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.amiName),
            availability_zone = vpc.availability_zones[1],
            block_devices = [kafkaProducerEc2BlockDevices],
            vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            key_pair = keyPair,
            security_group = sgKafkaProducer,
            user_data = ec2.UserData.for_linux(),
            role = ec2KafkaProducerRole
        )
        tags.of(kafkaProducerEC2Instance).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-kafkaProducerEC2Instance")
        tags.of(kafkaProducerEC2Instance).add("project", parameters.project)
        tags.of(kafkaProducerEC2Instance).add("env", parameters.env)
        tags.of(kafkaProducerEC2Instance).add("app", parameters.app)

        # kafkaProducerEC2Instance.user_data.add_commands(
        #     "sudo su",
        #     "sudo yum update -y",
        #     "sudo yum install python3 -y",
        #     "sudo yum install python3-pip -y",
        #     "sudo mkdir environment",
        #     "cd environment",
        #     "sudo yum install python3 virtualenv -y",
        #     "sudo python3 -m virtualenv alpaca-script",
        #     "source alpaca-script/bin/activate",
        #     "pip install -r <(aws s3 cp s3://kafka-flink-blog-bucket/python-scripts/requirement.txt -)",
        #     "aws s3 cp s3://kafka-flink-blog-bucket/python-scripts/ec2-script-historic.py .",
        #     "aws s3 cp s3://kafka-flink-blog-bucket/python-scripts/stock_mapper.py .",
        #     "export API_KEY=PKPBAXYRYGBBDNGOBYV9",
        #     "export SECRET_KEY=FC4vp8HUkno88tttRMYpONbOBTmcY9lcFXqc5msa",
        #     "export export BOOTSTRAP_SERVERS={bootstrap-server-endpoint}",
        #     "export KAFKA_SASL_MECHANISM=SCRAM-SHA-512",
        #     "export KAFKA_SASL_USERNAME={your-username}",
        #     "export KAFKA_SASL_PASSWORD={your-password}"
        # )

        customerManagedKey = kms.Key(self, "customerManagedKey",
            alias = "customer/msk",
            description = "Customer managed key",
            enable_key_rotation = True
        )
        tags.of(customerManagedKey).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-customerManagedKey")
        tags.of(customerManagedKey).add("project", parameters.project)
        tags.of(customerManagedKey).add("env", parameters.env)
        tags.of(customerManagedKey).add("app", parameters.app)

        # mskClusterSecrets = secretsmanager.Secret(self, "mskClusterSecrets",
        #     description = "Secrets for MSK Cluster",
        #     secret_name = f"AmazonMSK_/-{parameters.project}-{parameters.env}-{parameters.app}-secret",
        #     generate_secret_string = secretsmanager.SecretStringGenerator(),
        #     encryption_key=customerManagedKey
        # )

        # mskClusterPasswordSecretValue = mskClusterSecrets.secret_value
        # mskClusterPassword = mskClusterPasswordSecretValue.unsafe_unwrap()
        # ssm_parameter = ssm.StringParameter(self, "mskClusterPwdParamStore",
        #     parameter_name = f"blogAws-{parameters.env}-mskClusterPwd-ssmParamStore",
        #     string_value = mskClusterPassword,
        #     tier = ssm.ParameterTier.ADVANCED
        # )

        # mskClusterStorageInfo = msk.CfnCluster.StorageInfoProperty(
        #     ebs_storage_info = msk.CfnCluster.EBSStorageInfoProperty(
        #         volume_size = parameters.mskClusterVolumeSize
        #     )
        # )
        # mskClusterClientAuthentication = msk.CfnCluster.ClientAuthenticationProperty(
        #     sasl = msk.CfnCluster.SaslProperty(
        #         scram = msk.CfnCluster.ScramProperty(
        #             enabled = parameters.mskScramPropertyEnable
        #         )
        #     )
        # )
        # mskClusterEncryptionInfo = msk.CfnCluster.EncryptionInfoProperty(
        #     encryption_in_transit = msk.CfnCluster.EncryptionInTransitProperty(
        #         client_broker = parameters.mskEncryptionClientBroker,
        #         in_cluster = parameters.mskEncryptionInClusterEnable
        #     )
        # )
        # mskCluster = msk.CfnCluster(
        #     self, "mskCluster",
        #     cluster_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskCluster1",
        #     kafka_version = parameters.mskVersion,
        #     number_of_broker_nodes = parameters.mskNumberOfBrokerNodes,
        #     broker_node_group_info = msk.CfnCluster.BrokerNodeGroupInfoProperty(
        #         instance_type = parameters.mskClusterInstanceType,
        #         client_subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
        #         security_groups = [sgMskCluster.security_group_id],
        #         storage_info = mskClusterStorageInfo
        #     ),
        #     client_authentication = mskClusterClientAuthentication,
        #     encryption_info = mskClusterEncryptionInfo
        # )

        # batchScramSecret = msk.CfnBatchScramSecret(self, "mskBatchScramSecret",
        #     cluster_arn = mskCluster.attr_arn,
        #     secret_arn_list = [mskClusterSecrets.secret_arn]
        # )


        # batchScramSecret = msk.CfnBatchScramSecret(self, "batchScramSecret",
        #     cluster_arn = mskCluster.attr_arn,
        #     secret_arn_list = [mskClusterSecrets.secret_arn]
        # )
        
        # get_tls_brokers = cr.AwsCustomResource(self, "get_tls_brokers", 
        #     on_create=cr.AwsSdkCall(
        #         service="Kafka",
        #         action="getBootstrapBrokers",
        #         parameters={"ClusterArn": mskCluster.attr_arn},
        #         region=app_region,
        #         physical_resource_id=cr.PhysicalResourceId.of('TLS-BOOTSTRAP_BROKERS-'+app_region)
        #     ),
        #     policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
        #         resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
        #     )
        # )

        kafkaClientEc2BlockDevices = ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(10))
        kafkaClientEC2Instance = ec2.Instance(self, "kafkaClientEC2Instance",
            instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaClientEC2Instance",
            vpc = vpc,
            instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters.instanceClass), ec2.InstanceSize(parameters.instanceSize)),
            machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.amiName),
            availability_zone = vpc.availability_zones[1],
            block_devices = [kafkaClientEc2BlockDevices],
            vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            key_pair = keyPair,
            security_group = sgEc2MskCluster,
            user_data = ec2.UserData.for_linux(),
            role = ec2MskClusterRole
        )


        # kafkaClientEC2Instance.user_data.add_commands(
        #     "sudo su",
        #     "sudo yum update -y",
        #     "sudo yum -y install java-11",
        #     "wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz",
        #     "tar -xzf kafka_2.13-3.5.1.tgz",
        #     "cd kafka_2.13-3.5.1/libs",
        #     "wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar",
        #     "cd /home/ec2-user",
        #     "cat <<EOF > /home/ec2-user/user_jaas.conf",
        #     "KafkaClient {",
        #     f"    org.apache.kafka.common.security.scram.ScramLoginModule required",
        #     f"    username={parameters.username}",
        #     f"    password={ssm_parameter.string_value};",
        #     "};",
        #     "EOF",
        #     "export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
        #     "mkdir tmp",
        #     "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
        #     "cat <<EOF > /home/ec2-user/client_sasl.properties",
        #     f"security.protocol=SASL_SSL",
        #     f"sasl.mechanism=SCRAM-SHA-512",
        #     f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
        #     "EOF",
        #     # f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server {kafka_url} --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters.topic_name}"
        # )

        flinkAppLogGroup = logs.LogGroup(self, "apacheFlinkAppLogGroup",
            log_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-flinkAppLogGroup",
            retention = logs.RetentionDays.ONE_WEEK #parameters.flinkAppLogGroupRetentionDays
        )

        apacheFlinkAppRole = iam.Role(self, "apacheFlinkAppRole",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkAppRole",
            assumed_by=iam.ServicePrincipal("kinesisanalytics.amazonaws.com")
        )

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
                    )
                ]
            )
        )

        apacheFlinkApp = flink.Application(self, "apacheFlinkApp",
            code = flink.ApplicationCode.from_bucket(bucket = bucket,file_key = parameters.apacheFlinkBucketKey),
            runtime = flink.Runtime.FLINK_1_11, #(parameters.flinkRuntimeVersion),
            application_name = f"{parameters.project}-{parameters.env}-{parameters.app}-apacheFlinkApp",
            vpc = vpc,
            vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            auto_scaling_enabled = parameters.apacheFlinkAutoScalingEnable,
            property_groups = {
                "FlinkApplicationProperties": {
                    "kinesis.region" : parameters.apacheFlinkKinesisRegion, 
                    "kinesis.sink.stream" : parameters.apacheFlinkKinesisSinkStream,
                    "kinesis.source.stream": parameters.apacheFlinkKinesisSourceStream
                }
            },
            parallelism = parameters.apacheFlinkParallelism,
            parallelism_per_kpu = parameters.apacheFlinkParallelismPerKpu,
            checkpointing_enabled = parameters.apacheFlinkCheckpointingEnabled,
            log_group = flinkAppLogGroup
        )

################################################################################################################################################################     
        opensearch_access_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            actions=["es:*"],
            resources= ["*"]#[f"{openSearchDomain.domain_arn}/*"]
        )
        
        # openSearchSecrets = secretsmanager.Secret(self, "openSearchSecrets",
        #     description = "Secrets for OpenSearch",
        #     secret_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecrets",
        #     generate_secret_string = secretsmanager.SecretStringGenerator(
        #         secret_string_template = json.dumps({"username": parameters.username}),
        #         generate_string_key = "password"
        #     ),
        #     encryption_key=customerManagedKey
        # )

        openSearchSecrets = secretsmanager.Secret(self, "openSearchSecrets",
            description = "Secrets for OpenSearch",
            secret_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecrets",
            generate_secret_string = secretsmanager.SecretStringGenerator(),
            encryption_key=customerManagedKey
        )
        # openSearchSecretsUsername = secretsmanager.Secret(self, "openSearchSecretsUsername",
        #     description = "Secrets for OpenSearch",
        #     secret_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchUsernameSecret",
        #     generate_secret_string = secretsmanager.SecretStringGenerator(
        #         secret_string_template = json.dumps({"username": parameters.username})
        #     ),
        #     encryption_key=customerManagedKey
        # )

        # openSearchSecretsUsernameValue = openSearchSecretsUsername.secret_value
        openSearchMasterPasswordSecretValue = openSearchSecrets.secret_value
        openSearchMaster = openSearchMasterPasswordSecretValue.unsafe_unwrap()
        
        # ssm_parameter = ssm.StringParameter(self, "openSearchParameter",
        #     parameter_name = "openSearchParameter",
        #     string_value = openSearchMaster,
        #     tier = ssm.ParameterTier.ADVANCED
        # )

        OPENSEARCH_VERSION = parameters.openSearchVersion
        openSearchDomain = opensearch.Domain(self, "openSearchDomain",
            domain_name = f"awsblog-{parameters.env}-public-domain1",
            version = opensearch.EngineVersion.open_search(OPENSEARCH_VERSION),
            capacity = opensearch.CapacityConfig(
                multi_az_with_standby_enabled = parameters.multiAzWithStandByEnabled,
                master_nodes = parameters.no_of_master_nodes,
                master_node_instance_type = parameters.master_node_instance_type,
                data_nodes = parameters.no_of_data_nodes,
                data_node_instance_type = parameters.data_node_instance_type
            ),
            ebs = opensearch.EbsOptions(
                volume_size = parameters.openSearchVolumeSize,
                volume_type = ec2.EbsDeviceVolumeType.GP3
            ),
            access_policies = [opensearch_access_policy],
            enforce_https = parameters.openSearchEnableHttps,                      # Required when FGAC is enabled
            node_to_node_encryption = parameters.openSearchNodeToNodeEncryption,   # Required when FGAC is enabled
            encryption_at_rest = opensearch.EncryptionAtRestOptions(
                enabled = parameters.openSearchEncryptionAtRest
            ),
            fine_grained_access_control = opensearch.AdvancedSecurityOptions(
                master_user_name = parameters.openSearchMasterUsername,
                master_user_password = openSearchMasterPasswordSecretValue
            )
            # vpc=vpc,
            # vpc_subnets = [ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC)]
            # vpc_subnets = [
            #     ec2.SubnetSelection(
            #         subnet_type=ec2.SubnetType.PUBLIC,
            #         subnet_filters=ec2.SubnetFilter.availability_zones(["availabilityZones"]) #[ec2.SubnetFilter("name": "availability-zone", "values": ["us-east-1a"])]
            #     )
            # ]
            # zone_awareness = opensearch.ZoneAwarenessConfig(
            #     availability_zone_count = parameters.openSearchAvailabilityZoneCount,
            #     enabled = parameters.openSearchAvailabilityZoneEnable
            # )
        )
################################################################################################################################################################
        CfnOutput(self, "vpcId",
            value = vpc.vpc_id,
            description = "VPC Id",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-vpcId"
        )
        # CfnOutput(self, "publicSubnetId",
        #     value=vpc.public_subnets,
        #     description = "Public Subnet Id",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-publicSubnetId"
        # )
        # CfnOutput(self, "privateSubnetId",
        #     value=vpc.private_subnets,
        #     description = "Private Subnet Id",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-privateSubnetId"
        # )
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
        CfnOutput(self, "ec2KafkaProducerRoleArn",
            value=ec2KafkaProducerRole.role_arn,
            description = "ARN of EC2 kafka producer role",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-ec2KafkaProducerRoleArn"
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
        CfnOutput(self, "kafkaProducerEC2InstanceId",
            value=kafkaProducerEC2Instance.instance_id,
            description = "Kafka producer EC2 instance Id",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaProducerEC2InstanceId"
        )
        CfnOutput(self, "kafkaClientEC2InstanceId",
            value=kafkaClientEC2Instance.instance_id,
            description = "Kafka client EC2 instance Id",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaClientEC2InstanceId"
        )
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
        # CfnOutput(self, "openSearchSecretsArn",
        #     value=openSearchSecrets.secret_arn,
        #     description = "ARN of MSK cluster secrets",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecretsArn"
        # )
        # CfnOutput(self, "openSearchSecretsName",
        #     value=openSearchSecrets.secret_name,
        #     description = "MSK cluster secrets name",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecretsName"
        # )
        # CfnOutput(self, "openSearchDomainName",
        #     value=openSearchDomain.domain_name,
        #     description = "OpenSearch domain name",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchDomainName"
        # )
        # CfnOutput(self, "openSearchDomainEndpoint",
        #     value=openSearchDomain.domain_endpoint,
        #     description = "OpenSearch domain endpoint",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchDomainEndpoint"
        # )
