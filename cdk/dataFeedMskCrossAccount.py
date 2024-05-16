from constructs import Construct
from aws_cdk import (
    Stack,
    CfnOutput,
    aws_ec2 as ec2,
    aws_iam as iam,
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
    aws_kinesisanalytics_flink_alpha as flink,
    Aws as AWS
)
from . import parameters


class dataFeedMskCrossAccount(Stack):

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

        sgConsumerEc2 = ec2.SecurityGroup(self, "sgConsumerEc2",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgConsumerEc2",
            vpc=vpc,
            description="Security group associated with the EC2 instance of MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgConsumerEc2).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-sgConsumerEc2")
        tags.of(sgConsumerEc2).add("project", parameters.project)
        tags.of(sgConsumerEc2).add("env", parameters.env)
        tags.of(sgConsumerEc2).add("app", parameters.app)

        sgConsumerEc2.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "Allow SSH access from the internet")

        sgConsumerEc2.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgKafkaInboundPort, parameters.sgKafkaOutboundPort),
            description = "Allow Custom TCP traffic from sgConsumerEc2 to sgMskCluster"
        )

        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgConsumerEc2.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from sgConsumerEc2 to sgMskCluster"
        )
        sgMskCluster.add_ingress_rule(
            peer = ec2.Peer.security_group_id(sgMskCluster.security_group_id),
            connection = ec2.Port.tcp_range(parameters.sgMskClusterInboundPort, parameters.sgMskClusterOutboundPort),
            description = "Allow all TCP traffic from sgMskCluster to sgMskCluster"
        )

        consumerEc2Role = iam.Role(self, "consumerEc2Role",
            role_name = f"{parameters.project}-{parameters.env}-{parameters.app}-consumerEc2Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        tags.of(consumerEc2Role).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-consumerEc2Role")
        tags.of(consumerEc2Role).add("project", parameters.project)
        tags.of(consumerEc2Role).add("env", parameters.env)
        tags.of(consumerEc2Role).add("app", parameters.app)

        consumerEc2Role.attach_inline_policy(
            iam.Policy(self, 'ec2MskClusterPolicy',
                statements = [
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
                            "kafka:ListClusters",
                            "kafka:DescribeCluster",
                            "kafka-cluster:Connect",
                            "kafka-cluster:ReadData",
                            "kafka:DescribeClusterV2",
                            "kafka-cluster:CreateTopic",
                            "kafka-cluster:DeleteTopic",
                            "kafka-cluster:AlterCluster",
                            "kafka-cluster:WriteData",
                            "kafka-cluster:AlterGroup",
                            "kafka-cluster:DescribeGroup",
                            "kafka-cluster:DescribeClusterDynamicConfiguration",
                        ],
                        resources= [parameters.mskClusterArn,
                            f"arn:aws:kafka:{AWS.REGION}:{AWS.ACCOUNT_ID}:topic/{parameters.mskClusterName}/*/*",
                            f"arn:aws:kafka:{AWS.REGION}:{AWS.ACCOUNT_ID}:group/{parameters.mskClusterName}/*/*"
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
                            "s3:GetObject",
                            "s3:PutObject"
                        ],
                        resources = [f"arn:aws:s3:::{parameters.s3BucketName}",
                                    f"arn:aws:s3:::{parameters.s3BucketName}/*"
                        ]
                    )
                ]
            )
        )
        
        kafkaClientEc2BlockDevices = ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(10))
        kafkaConsumerEC2Instance = ec2.Instance(self, "kafkaConsumerEC2Instance",
            instance_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaConsumerEC2Instance",
            vpc = vpc,
            instance_type = ec2.InstanceType.of(ec2.InstanceClass(parameters.ec2InstanceClass), ec2.InstanceSize(parameters.ec2InstanceSize)),
            machine_image = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2), #ec2.MachineImage().lookup(name = parameters.amiName),
            availability_zone = vpc.availability_zones[1],
            block_devices = [kafkaClientEc2BlockDevices],
            vpc_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            key_pair = keyPair,
            security_group = sgConsumerEc2,
            user_data = ec2.UserData.for_linux(),
            role = consumerEc2Role
        )
        tags.of(kafkaConsumerEC2Instance).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaConsumerEC2Instance")
        tags.of(kafkaConsumerEC2Instance).add("project", parameters.project)
        tags.of(kafkaConsumerEC2Instance).add("env", parameters.env)
        tags.of(kafkaConsumerEC2Instance).add("app", parameters.app)

        kafkaConsumerEC2Instance.user_data.add_commands(
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
            f'    password="{parameters.mskClusterPwdParamStoreValue}";',
            "};",
            "EOF",
            "echo 'export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf' >> ~/.bashrc",
            "mkdir tmp",
            "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
            "cat <<EOF > /home/ec2-user/client_sasl.properties",
            f"security.protocol=SASL_SSL",
            f"sasl.mechanism=SCRAM-SHA-512",
            f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
            "EOF",
        )
    
        mskClusterVpcConnection = msk.CfnVpcConnection(self, "mskClusterVpcConnection",
            authentication="SASL_SCRAM",
            client_subnets=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
            security_groups=[sgMskCluster.security_group_id],
            target_cluster_arn=parameters.mskClusterArn,
            vpc_id=vpc.vpc_id
        )
        tags.of(mskClusterVpcConnection).add("name", f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterVpcConnection")
        tags.of(mskClusterVpcConnection).add("project", parameters.project)
        tags.of(mskClusterVpcConnection).add("env", parameters.env)
        tags.of(mskClusterVpcConnection).add("app", parameters.app)

#############       Output Values      #############

        CfnOutput(self, "vpcId",
            value = vpc.vpc_id,
            description = "VPC Id",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-vpcId"
        )
        CfnOutput(self, "sgMskClusterId",
            value = sgMskCluster.security_group_id,
            description = "Security group ID of the MSK cluster attached to mskClusterVpcConnection",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgMskClusterId"
        )
        CfnOutput(self, "sgConsumerEc2Id",
            value = sgConsumerEc2.security_group_id,
            description = "Security group ID of the EC2 consumer for the MSK cluster",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgConsumerEc2Id"
        )
        CfnOutput(self, "consumerEc2RoleArn",
            value = consumerEc2Role.role_arn,
            description = "ARN of EC2 MSK cluster role",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-consumerEc2RoleArn"
        )
        CfnOutput(self, "kafkaConsumerEC2InstanceId",
            value = kafkaConsumerEC2Instance.instance_id,
            description = "Kafka client EC2 instance Id",
            export_name = f"{parameters.project}-{parameters.env}-{parameters.app}-kafkaConsumerEC2InstanceId"
        )