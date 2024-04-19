        # # asset = Asset(self, "userDataAsset",
        # #     path="./userData.sh"
        # # )

        # # local_path = kafkaClientEC2Instance.user_data.add_s3_download_command(
        # #     bucket=asset.bucket,
        # #     bucket_key=asset.s3_object_key,
        # #     region="us-east-1"
        # # )


 # kafkaClientSecurityGroupId = ec2.SecurityGroup.from_security_group_id(self, "kafkaClientSecurityGroup", sgEc2MskCluster.security_group_id)

        # print(f"Security Group ID: {sgEc2MskCluster.security_group_id}")
        # print(f"Key Pair Name: {parameters.keyPairName}")

        # key_pair = ec2.KeyPair(self, "MyKeyPair",
        #     key_pair_name=parameters.keyPairName,
        #     account = parameters.accountId,
        #     region = parameters.region,
        #     type = ec2.KeyPairType(parameters.keyPairType),
        #     format = ec2.KeyPairFormat(parameters.keyPairFormat),
        #     physical_name = f"{parameters.project}-{parameters.env}-{parameters.app}-{parameters.region}"
        # )


            # tags = {
            #     "Name": f"{parameters.project}-{parameters.env}-{parameters.app}",
            #     "project": parameters.project,
            #     "env": parameters.env,
            #     "app": parameters.app
            # }


# lambdaFunctionExecutionRole.add_to_policy(my_file_system_policy)

        # vpc.add_tags(
        #     Name=f"{parameters.project}-{parameters.env}-{parameters.authorName}-{parameters.app}-vpc",
        #     Author=f"{parameters.authorName}",
        #     project=f"{parameters.project}",
        #     env=f"{parameters.env}",
        #     app=f"{parameters.app}"
        # )

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

                # ssm_parameter_value = json.loads(mskClusterPasswordSecretValue.to_string())
                # ssm_parameter_value = json.loads(mskClusterPasswordSecretValue.secret_value.to_string())
                # password = ssm_parameter_value["password"]

password_value = mskClusterPasswordSecretValue.to_string()
password_json = json.loads(password_value)
password = password_json["password"]
msk_cluster_password_secret_value = mskClusterPasswordSecretValue.unsafe_unwrap() #

        # mskClusterPassword = secretsmanager.Secret.from_secret_name_v2(
        #     self, "mskClusterPassword",
        #     secret_name = secretManager.secret_name
        # )