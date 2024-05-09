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
            "zookeeper.session.timeout.ms=18000",
            "allow.everyone.if.no.acl.found=false"
        ]
        mskClusterConfigProperties = "\n".join(mskClusterConfigProperties)
        mskClusterConfiguration = msk.CfnConfiguration(self, "mskClusterConfiguration",
            name = f"{parameters.project}-{parameters.env}-{parameters.app}-mskClusterConfiguration",
            server_properties = mskClusterConfigProperties,
            description = "MSK cluster configuration"
        )

        mskCluster.add_property_override(
            'BrokerNodeGroupInfo.ConnectivityInfo',
            {
                'VpcConnectivity': {
                    'ClientAuthentication': {
                        'Sasl': {
                            'Iam': {'Enabled': False},
                            'Scram': {'Enabled': True}
                        },
                        'Tls': {'Enabled': False}
                    }
                }
            }
        )

        mskCluster.add_property_override(
            'ConfigurationInfo',
            {
                "arn": mskClusterConfiguration.attr_arn,
                "revision": mskClusterConfiguration.attr_latest_revision_revision
            }
        )

        mskClusterPolicy = msk.CfnClusterPolicy(self, "mskClusterPolicy",
            cluster_arn=mskClusterArnParamStoreValue,
            policy={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": [parameters.mskCrossAccountId]
                        },
                        "Action": [
                            "kafka:CreateVpcConnection",
                            "kafka:GetBootstrapBrokers",
                            "kafka:DescribeCluster",
                            "kafka:DescribeClusterV2"
                        ],
                        "Resource": mskClusterArnParamStoreValue
                    }
                ]
            }
        )
        mskClusterPolicy.node.