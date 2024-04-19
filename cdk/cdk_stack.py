from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    CfnOutput,
    # path as path,
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
    # aws_msk_alpha as msk_alpha,
    aws_secretsmanager as secretsmanager,
    aws_opensearchservice as opensearch,
    aws_kms as kms,
    aws_logs as logs,
    Tags as tags,
    aws_opensearchservice as opensearch
    # aws_kinesisanalytics_flink_alpha as flink
)
# import * as cdk from 'aws-cdk-lib';
# const accountId = cdk.Aws.ACCOUNT_ID;
# const region = cdk.Aws.REGION;
from . import parameters
import aws_cdk.aws_kinesisanalytics_flink_alpha as flink
import json
import os.path

app_region = os.environ["CDK_DEFAULT_REGION"]

class dataFeedMskAwsBlogStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc (self, "vpc",
            ip_addresses = ec2.IpAddresses.cidr(parameters.cidr_range),
            enable_dns_hostnames = parameters.enable_dns_hostnames,
            enable_dns_support = parameters.enable_dns_support,
            availability_zones = ["us-east-1a", "us-east-1b"],
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
        tags.of(vpc).add("Environment", "Dev")
        # tags.of(vpc.node).add("Environment", "Dev")
        # tags.of(node).add("Environment", "Dev")

        sgEc2MskCluster = ec2.SecurityGroup(self, "sgEc2MskCluster",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgEc2MskCluster",
            vpc=vpc,
            description="Security group associated with the EC2 instance of MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        sgEc2MskCluster.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "Allow SSH access from the internet")
        tags.of(sgEc2MskCluster).add("Environment", "Dev")

        sgLambdaFunction = ec2.SecurityGroup(self, "sgLambdaFunction",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgLambdaFunction",
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

        sgMskCluster.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgEc2MskCluster.security_group_id),
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from sgEc2MskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from sgMskCluster to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgLambdaFunction.security_group_id),
            connection=ec2.Port.tcp_range(9092, 9098),
            description="Allow TCP traffic on port range (9092 - 9098) from security group sgLambdaFunction to security group sgMskCluster"
        )

        sgLambdaFunction.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection=ec2.Port.tcp_range(9092, 9098),
            description="Allow TCP traffic on port range (9092 - 9098) from security group sgMskCluster to security group sgLambdaFunction"
        )

        bucket = s3.Bucket.from_bucket_name(self, "MyBucket", parameters.bucket_name)
        
        ec2MskClusterRole = iam.Role(self, "ec2MskClusterRole",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-ec2MskClusterRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        
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

        lambdaFunctionExecutionRole = iam.Role(self, "lambdaExecutionRole",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-lambdaFunctionExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
        )

        lambdaFunctionExecutionRole.attach_inline_policy(
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

        lambdaFunction =_lambda.Function(self, "lambdaFunction",
            function_name = f"{parameters.project}-{parameters.env}-{parameters.app}-lambdaFunction",
            runtime = getattr(_lambda.Runtime, parameters.lambdaRuntimeVersion),
            handler = parameters.lambdaFunctionHandler,
            timeout = Duration.seconds(parameters.lambdaTimeout),
            code = _lambda.Code.from_bucket(bucket = bucket,key = parameters.bucket_key),
            role = lambdaFunctionExecutionRole  
        )

        # kafkaProducerEC2Instance = ec2.Instance(self, "kafkaProducerEC2Instance",
        #     instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaProducerEC2Instance",
        #     vpc = vpc,
        #     instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters.instanceClass), ec2.InstanceSize(parameters.instanceSize)),
        #     machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.amiName),
        #     availability_zone = vpc.availability_zones[1],
        #     # block_devices = ec2.BlockDevice(
        #     #     device_name="deviceName",
        #     #     volume=ec2.BlockDeviceVolume.ebs(8)
        #     # ),
        #     vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        #     key_pair = keyPair,
        #     security_group = sgEc2MskCluster,
        #     user_data = ec2.UserData.for_linux(),
        #     role = ec2MskClusterRole
        # )
        
        customerManagedKey = kms.Key(self, "customerManagedKey",
            alias = "customer/msk",
            description = "Customer managed key",
            enable_key_rotation = True
        )

        secretManager = secretsmanager.Secret(self, "mskClusterSecrets",
            description = "Secrets for MSK Cluster",
            secret_name = f"AmazonMSK_/-{parameters.project}-{parameters.env}-{parameters.app}-secret",
            generate_secret_string = secretsmanager.SecretStringGenerator(),
            encryption_key=customerManagedKey
        )

        mskClusterPasswordSecretValue = secretManager.secret_value
        mskClusterPassword = mskClusterPasswordSecretValue.unsafe_unwrap()
        print(type(mskClusterPassword))
        ssm_parameter = ssm.StringParameter(self, "mySsmParameter",
            parameter_name = "mySsmParameter",
            string_value = mskClusterPassword,
            tier = ssm.ParameterTier.ADVANCED
        )

        mskCluster = msk.CfnCluster(
            self, "mskCluster",
            cluster_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskCluster",
            kafka_version = parameters.mskVersion,
            number_of_broker_nodes = parameters.mskNumberOfBrokerNodes,
            broker_node_group_info = msk.CfnCluster.BrokerNodeGroupInfoProperty(
                instance_type = parameters.mskClusterInstanceType,
                client_subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
                security_groups = [sgMskCluster.security_group_id],
                storage_info = msk.CfnCluster.StorageInfoProperty(
                    ebs_storage_info = msk.CfnCluster.EBSStorageInfoProperty(
                        volume_size = parameters.mskClusterVolumeSize
                    )
                )
            ),
            client_authentication = msk.CfnCluster.ClientAuthenticationProperty(
                sasl = msk.CfnCluster.SaslProperty(
                    scram = msk.CfnCluster.ScramProperty(
                        enabled = parameters.mskScramPropertyEnable
                    )
                )
            ),
            encryption_info = msk.CfnCluster.EncryptionInfoProperty(
                encryption_in_transit = msk.CfnCluster.EncryptionInTransitProperty(
                    client_broker = parameters.mskEncryptionClientBroker,
                    in_cluster = parameters.mskEncryptionInClusterEnable
                )
            )
        )

        # batchScramSecret = msk.CfnBatchScramSecret(self, "batchScramSecret",
        #     cluster_arn = mskCluster.attr_arn,
        #     secret_arn_list = [secretManager.secret_arn]
        # )
        # batchScramSecret = msk.CfnBatchScramSecret(self, "batchScramSecret",
        #     cluster_arn = mskCluster.attr_arn,
        #     secret_arn_list = [secretManager.secret_arn]
        # )
        
        get_tls_brokers = cr.AwsCustomResource(self, "get_tls_brokers", 
            on_create=cr.AwsSdkCall(
                service="Kafka",
                action="getBootstrapBrokers",
                parameters={"ClusterArn": mskCluster.attr_arn},
                region=app_region,
                physical_resource_id=cr.PhysicalResourceId.of('TLS-BOOTSTRAP_BROKERS-'+app_region)
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
            )
        )

        keyPair = ec2.KeyPair.from_key_pair_name(self, "MyKeyPair", parameters.keyPairName)

        kafkaClientEC2Instance = ec2.Instance(self, "kafkaClientEC2Instance",
            instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaClientEC2Instance",
            vpc = vpc,
            instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters.instanceClass), ec2.InstanceSize(parameters.instanceSize)),
            machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.amiName),
            availability_zone = vpc.availability_zones[1],
            # block_devices = ec2.BlockDevice(
            #     device_name="deviceName",
            #     volume=ec2.BlockDeviceVolume.ebs(8)
            # ),
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
            "wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz",
            "tar -xzf kafka_2.13-3.5.1.tgz",
            "cd kafka_2.13-3.5.1/libs",
            "wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar",
            "cd /home/ec2-user",
            "cat <<EOF > /home/ec2-user/user_jaas.conf",
            "KafkaClient {",
            f"    org.apache.kafka.common.security.scram.ScramLoginModule required",
            f"    username={parameters.username}",
            f"    password={ssm_parameter.string_value};",
            "};",
            "EOF",
            "export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
            "mkdir tmp",
            "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
            "cat <<EOF > /home/ec2-user/client_sasl.properties",
            f"security.protocol=SASL_SSL",
            f"sasl.mechanism=SCRAM-SHA-512",
            f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
            "EOF",
            # f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server {kafka_url} --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters.topic_name}"
        )

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
        
        opensearch_access_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            actions=["es:*"],
            resources= ["*"]#[f"{openSearchDomain.domain_arn}/*"]
        )
        
        # openSearchSecretManager = secretsmanager.Secret(self, "openSearchSecrets",
        #     description = "Secrets for OpenSearch",
        #     secret_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecrets",
        #     generate_secret_string = secretsmanager.SecretStringGenerator(
        #         secret_string_template = json.dumps({"username": parameters.username}),
        #         generate_string_key = "password"
        #     ),
        #     encryption_key=customerManagedKey
        # )

        openSearchSecretManager = secretsmanager.Secret(self, "openSearchSecrets",
            description = "Secrets for OpenSearch",
            secret_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchSecrets",
            generate_secret_string = secretsmanager.SecretStringGenerator(),
            encryption_key=customerManagedKey
        )
        # openSearchSecretManagerUsername = secretsmanager.Secret(self, "openSearchSecretsUsername",
        #     description = "Secrets for OpenSearch",
        #     secret_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchUsernameSecret",
        #     generate_secret_string = secretsmanager.SecretStringGenerator(
        #         secret_string_template = json.dumps({"username": parameters.username})
        #     ),
        #     encryption_key=customerManagedKey
        # )

        # openSearchSecretManagerUsernameValue = openSearchSecretManagerUsername.secret_value
        openSearchMasterPasswordSecretValue = openSearchSecretManager.secret_value
        openSearchMaster = openSearchMasterPasswordSecretValue.unsafe_unwrap()
        
        ssm_parameter = ssm.StringParameter(self, "openSearchParameter",
            parameter_name = "openSearchParameter",
            string_value = openSearchMaster,
            tier = ssm.ParameterTier.ADVANCED
        )
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
                master_user_name = parameters.username,
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
        # CfnOutput(self, "secretValue",
        #     value=secretManager.secret_value.to_string(),
        #     description="Value of the secret stored in AWS Secrets Manager"
        # )
        # CfnOutput(
        #     self, "BootstrapBrokersSaslScram",
        #     value = mskCluster.attr_bootstrap_brokers_sasl_scram,
        #     description = "Bootstrap Brokers with SASL SCRAM authentication"
        # )
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
        # openSearchSecretManager.grant_read(
        #     grantee=iam.AccountPrincipal("095773313313")  # Replace with the account ID or IAM user/role
        # )
        # # openSearchSecretManager.grant_read(...)
        # # open_search_password_value = openSearchMasterPasswordSecretValue.to_string()
        # CfnOutput(self, "openSearchPasswordValue",
        #     value = openSearchMasterPasswordSecretValue.to_string(),
        #     description = "Open Search Password value",
        #     export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-openSearchPasswordValue"
        # )
