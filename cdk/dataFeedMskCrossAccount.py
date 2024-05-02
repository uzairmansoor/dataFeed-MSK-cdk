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
    aws_kinesisanalytics_flink_alpha as flink
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

        sgEc2MskCluster = ec2.SecurityGroup(self, "sgEc2MskCluster",
            security_group_name = f"{parameters.project}-{parameters.env}-{parameters.app}-sgEc2MskCluster",
            vpc=vpc,
            description="Security group associated with the EC2 instance of MSK Cluster",
            allow_all_outbound=True,
            disable_inline_rules=True
        )
        tags.of(sgEc2MskCluster).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-sgEc2MskCluster")
        tags.of(sgEc2MskCluster).add("project", parameters.project)
        tags.of(sgEc2MskCluster).add("env", parameters.env)
        tags.of(sgEc2MskCluster).add("app", parameters.app)

        sgEc2MskCluster.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "Allow SSH access from the internet")

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
        #     "sudo yum install jq -y",
        #     "wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz",
        #     "tar -xzf kafka_2.13-3.5.1.tgz",
        #     "cd kafka_2.13-3.5.1/libs",
        #     "wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar",
        #     "cd /home/ec2-user",
        #     "cat <<EOF > /home/ec2-user/users_jaas.conf",
        #     "KafkaClient {",
        #     f"    org.apache.kafka.common.security.scram.ScramLoginModule required",
        #     f'    username="{parameters.username}"',
        #     f'    password="{mskClusterPwdParamStoreValue}";',
        #     "};",
        #     "EOF",
        #     "export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
        #     f"broker_url=$(aws kafka get-bootstrap-brokers --cluster-arn {mskCluster.attr_arn} --region {parameters.region}| jq -r '.BootstrapBrokerStringSaslScram')",
        #     "mkdir tmp",
        #     "cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks",
        #     "cat <<EOF > /home/ec2-user/client_sasl.properties",
        #     f"security.protocol=SASL_SSL",
        #     f"sasl.mechanism=SCRAM-SHA-512",
        #     f"ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks",
        #     "EOF",
        #     f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server \"$broker_url\" --command-config /home/ec2-user/client_sasl.properties --create --topic {parameters.topic_name}"
        #     # f"/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server \"$broker_url\" --list --command-config ./client_sasl.properties"
        # )
    
        # mskClusterVpcConnection = msk.CfnVpcConnection(self, "mskClusterVpcConnection",
        #     authentication="SASL_SCRAM",
        #     client_subnets=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids[:2],
        #     security_groups=["sg-0ed1cc8700efdbe34"], #[sgMskCluster.security_group_id],
        #     target_cluster_arn="arn:aws:kafka:us-east-1:095773313313:cluster/awsblog-dev-app-mskCluster/9e99f14f-b7de-48e0-ba8a-6f70f6d5e106-24",
        #     vpc_id=vpc.vpc_id
        # )
        # tags.of(mskClusterVpcConnection).add("name", f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-mskClusterVpcConnection")
        # tags.of(mskClusterVpcConnection).add("project", parameters.project)
        # tags.of(mskClusterVpcConnection).add("env", parameters.env)
        # tags.of(mskClusterVpcConnection).add("app", parameters.app)