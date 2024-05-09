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
    aws_msk_alpha as mskAlpha,
    
)
from . import parameters_copy_dump
from . import dataFeedMsk_copy_dump

class importMskCluster(Stack):

    def __init__(self, scope: Construct, construct_id: str, msk_cluster_arn, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        import_msk_cluster = mskAlpha.Cluster.from_cluster_arn(self, "importMskClusterName", cluster_arn = msk_cluster_arn)

        
        # print("IMPORT", import_msk_cluster.cluster_arn)

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

        mskClusterConfigProperties = "\n".join(mskClusterConfigProperties)
        mskClusterConfiguration = msk.CfnConfiguration(self, "mskClusterConfiguration",
            name = f"{parameters_copy_dump.project}-{parameters_copy_dump.env}-{parameters_copy_dump.app}-mskClusterConfiguration",
            server_properties = mskClusterConfigProperties,
            description = "MSK cluster configuration"
        )
    
        # # cluster_configuration_info = mskAlpha.ClusterConfigurationInfo(
        # #     arn=mskClusterConfiguration.attr_arn,
        # #     revision=mskClusterConfiguration.attr_latest_revision_revision
        # # )

        import_msk_cluster.
        import_msk_cluster.ClusterConfigurationInfo(
            arn=mskClusterConfiguration.attr_arn,
            revision=mskClusterConfiguration.attr_latest_revision_revision
        )

    
        # import_msk_cluster.configuration_info = [mskClusterConfiguration]
       
        