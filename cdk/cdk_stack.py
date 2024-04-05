from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    CfnOutput,
    path as path,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_sns_subscriptions as subs,
    aws_signer as signer,
    aws_lambda as _lambda,
    aws_s3 as s3,
    aws_iam as iam,
    aws_msk as msk,
    # aws_msk_alpha as msk_alpha,
    aws_secretsmanager as secretsmanager,
    aws_kms as kms,
    aws_cloudwatch as cloudwatch
    # aws_s3_assets as Asset
    aws_kinesisanalytics_flink_alpha as flink
)
from . import parameters
import json

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

        sgEc2MskCluster = ec2.SecurityGroup(self, "sgEc2MskCluster",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgEc2MskCluster",
            vpc=vpc,
            description="Security group associated with the EC2 instance of MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        sgEc2MskCluster.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "Allow SSH access from the internet")

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
        
        ec2MskClusterRole.add_to_policy(iam.PolicyStatement(
            actions=[
                "kafka:ListClusters",
                "kafka:DescribeCluster"
            ],
            resources= ["*"] #["arn:aws:kafka:*:*:cluster/*"]
        ))

        ec2MskClusterRole.add_to_policy(iam.PolicyStatement(
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
        ))

        ec2MskClusterRole.add_to_policy(iam.PolicyStatement(
            actions=[
                "s3:*",
                "s3-object-lambda:*"
            ],
            resources= ["*"] #["arn:aws:kafka:*:*:cluster/*"]
        ))

        lambdaFunctionExecutionRole = iam.Role(self, "lambdaExecutionRole",
        role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-lambdaFunctionExecutionRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
        )

# Attach the policy to the IAM role
        lambdaFunctionExecutionRole.add_to_policy(iam.PolicyStatement(
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
        ))

        lambdaFunctionExecutionRole.add_to_policy(iam.PolicyStatement(
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
        ))

        _lambda.Function(self, "lambdaFunction",
            function_name = f"{parameters.project}-{parameters.env}-{parameters.app}-lambdaFunction",
            runtime = getattr(_lambda.Runtime, parameters.lambdaRuntimeVersion),
            handler = parameters.lambdaFunctionHandler,
            timeout = Duration.seconds(parameters.lambdaTimeout),
            code = _lambda.Code.from_bucket(bucket = bucket,key = parameters.bucket_key),
            role = lambdaFunctionExecutionRole  
        )
        
        customerManagedKey = kms.Key(self, "customerManagedKey",
            alias = "customer/msk",
            description = "Customer managed key",
            enable_key_rotation = True
        )

        secretManager = secretsmanager.Secret(self, "mskClusterSecrets",
            description = "Secrets for MSK Cluster",
            secret_name = f"AmazonMSK_/-{parameters.project}-{parameters.env}-{parameters.app}-secret",
            generate_secret_string = secretsmanager.SecretStringGenerator(
                secret_string_template = json.dumps({"username": parameters.username}),
                generate_string_key = "password"
            ),
            encryption_key=customerManagedKey
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

        # mskAlphaCluster = msk_alpha.Cluster(
        #     self, "mskAlphaCluster",
        #     cluster_name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskAlphaCluster",
        #     kafka_version = parameters.mskVersion,
        #     number_of_broker_nodes = parameters.mskNumberOfBrokerNodes,
        #     instance_type = parameters.mskClusterInstanceType,
        #     vpc_subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
        #     security_groups = [sgMskCluster.security_group_id],
        #     ebs_storage_info = msk_alpha.Cluster.EbsStorageInfo(
        #         # encryption_key = key,
        #         volume_size = parameters.mskClusterVolumeSize
        #     ),
        #     client_authentication = msk_alpha.ClientAuthentication.sasl(
        #         scram = parameters.mskScramPropertyEnable
        #     ),
        #     encryption_in_transit = msk.EncryptionInTransitConfig(
        #         client_broker = msk.ClientBrokerEncryption(parameters.mskEncryptionClientBroker),
        #         enable_in_cluster = parameters.mskEncryptionInClusterEnable
        #     )
        # )

        batchScramSecret = msk.CfnBatchScramSecret(self, "batchScramSecret",
            cluster_arn = mskCluster.attr_arn,
            secret_arn_list = [secretManager.secret_arn]
        )
        
        key_pair = ec2.KeyPair.from_key_pair_name(self, "MyKeyPair", parameters.keyPairName)

        kafkaClientEC2Instance = ec2.Instance(self, "kafkaClientEC2Instance",
            instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaClientEC2Instance",
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass(parameters.instanceClass), ec2.InstanceSize(parameters.instanceSize)),
            machine_image= ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.amiName),
            availability_zone = vpc.availability_zones[1],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            key_pair = key_pair,
            security_group = sgEc2MskCluster,
            user_data = ec2.UserData.for_linux(),
            role = ec2MskClusterRole
        )
        secret_value = secretManager.secret_value_from_json("username")
        secret_string = secret_value.to_string()
        # print(f"secret_string: {secret_string}")
        # secret_dict = json.loads(secret_string)
        # username = secret_dict["username"]
        # password = secret_dict["password"]

        # print(f"username: {username}")
        # print(f"password: {password}")

        # broker_url = mskCluster.ClientAuthenticationProperty.

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
            # f"    username=\"{username}\"",
            # f"    password=\"{password}\";",
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

        flink_app = flink.Application(stack, "flinkApp",
            code = flink.ApplicationCode.from_asset(path.join(__dirname, "code-asset")),
            runtime = flink.Runtime.FLINK_1_18,
            application_name = f"{parameters.project}-{parameters.env}-{parameters.app}-flinkApp",
            auto_scaling_enabled = True,
            parallelism = 1,
            parallelism_per_kpu = 1,
            checkpointing_enabled = True
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

