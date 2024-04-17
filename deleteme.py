# The code below shows an example of how to instantiate this type.
# The values are placeholders you should change.
from aws_cdk import aws_msk as msk

cfn_cluster = msk.CfnCluster(self, "MyCfnCluster",
    broker_node_group_info=msk.CfnCluster.BrokerNodeGroupInfoProperty(
        client_subnets=["clientSubnets"],
        instance_type="instanceType",

        # the properties below are optional
        broker_az_distribution="brokerAzDistribution",
        connectivity_info=msk.CfnCluster.ConnectivityInfoProperty(
            public_access=msk.CfnCluster.PublicAccessProperty(
                type="type"
            ),
            vpc_connectivity=msk.CfnCluster.VpcConnectivityProperty(
                client_authentication=msk.CfnCluster.VpcConnectivityClientAuthenticationProperty(
                    sasl=msk.CfnCluster.VpcConnectivitySaslProperty(
                        iam=msk.CfnCluster.VpcConnectivityIamProperty(
                            enabled=False
                        ),
                        scram=msk.CfnCluster.VpcConnectivityScramProperty(
                            enabled=False
                        )
                    ),
                    tls=msk.CfnCluster.VpcConnectivityTlsProperty(
                        enabled=False
                    )
                )
            )
        ),
        security_groups=["securityGroups"],
        storage_info=msk.CfnCluster.StorageInfoProperty(
            ebs_storage_info=msk.CfnCluster.EBSStorageInfoProperty(
                provisioned_throughput=msk.CfnCluster.ProvisionedThroughputProperty(
                    enabled=False,
                    volume_throughput=123
                ),
                volume_size=123
            )
        )
    ),
    cluster_name="clusterName",
    kafka_version="kafkaVersion",
    number_of_broker_nodes=123,

    # the properties below are optional
    client_authentication=msk.CfnCluster.ClientAuthenticationProperty(
        sasl=msk.CfnCluster.SaslProperty(
            iam=msk.CfnCluster.IamProperty(
                enabled=False
            ),
            scram=msk.CfnCluster.ScramProperty(
                enabled=False
            )
        ),
        tls=msk.CfnCluster.TlsProperty(
            certificate_authority_arn_list=["certificateAuthorityArnList"],
            enabled=False
        ),
        unauthenticated=msk.CfnCluster.UnauthenticatedProperty(
            enabled=False
        )
    ),
    configuration_info=msk.CfnCluster.ConfigurationInfoProperty(
        arn="arn",
        revision=123
    ),
    current_version="currentVersion",
    encryption_info=msk.CfnCluster.EncryptionInfoProperty(
        encryption_at_rest=msk.CfnCluster.EncryptionAtRestProperty(
            data_volume_kms_key_id="dataVolumeKmsKeyId"
        ),
        encryption_in_transit=msk.CfnCluster.EncryptionInTransitProperty(
            client_broker="clientBroker",
            in_cluster=False
        )
    ),
    enhanced_monitoring="enhancedMonitoring",
    logging_info=msk.CfnCluster.LoggingInfoProperty(
        broker_logs=msk.CfnCluster.BrokerLogsProperty(
            cloud_watch_logs=msk.CfnCluster.CloudWatchLogsProperty(
                enabled=False,

                # the properties below are optional
                log_group="logGroup"
            ),
            firehose=msk.CfnCluster.FirehoseProperty(
                enabled=False,

                # the properties below are optional
                delivery_stream="deliveryStream"
            ),
            s3=msk.CfnCluster.S3Property(
                enabled=False,

                # the properties below are optional
                bucket="bucket",
                prefix="prefix"
            )
        )
    ),
    open_monitoring=msk.CfnCluster.OpenMonitoringProperty(
        prometheus=msk.CfnCluster.PrometheusProperty(
            jmx_exporter=msk.CfnCluster.JmxExporterProperty(
                enabled_in_broker=False
            ),
            node_exporter=msk.CfnCluster.NodeExporterProperty(
                enabled_in_broker=False
            )
        )
    ),
    storage_mode="storageMode",
    tags={
        "tags_key": "tags"
    }
)