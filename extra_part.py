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

# password_value = mskClusterPasswordSecretValue.to_string()
# password_json = json.loads(password_value)
# password = password_json["password"]
# msk_cluster_password_secret_value = mskClusterPasswordSecretValue.unsafe_unwrap() #

        # mskClusterPassword = secretsmanager.Secret.from_secret_name_v2(
        #     self, "mskClusterPassword",
        #     secret_name = secretManager.secret_name
        # )

                # lambdaFunction =_lambda.Function(self, "lambdaFunction",
        #     function_name = f"{parameters.project}-{parameters.env}-{parameters.app}-lambdaFunction",
        #     runtime = getattr(_lambda.Runtime, parameters.lambdaRuntimeVersion),
        #     handler = parameters.lambdaFunctionHandler,
        #     timeout = Duration.seconds(parameters.lambdaTimeout),
        #     code = _lambda.Code.from_bucket(bucket = bucket,key = parameters.bucket_key),
        #     role = lambdaFunctionExecutionRole  
        # )

        # openSearchSecretManager.grant_read(
        #     grantee=iam.AccountPrincipal("095773313313")  # Replace with the account ID or IAM user/role
        # )
        # # openSearchSecretManager.grant_read(...)
        # # open_search_password_value = openSearchMasterPasswordSecretValue.to_string()

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
                        "echo 'export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf' >> ~/.bashrc",
                        "echo 'export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf",
                        f"export BOOTSTRAP_SERVERS=$(aws kafka get-bootstrap-brokers --cluster-arn {mskCluster.attr_arn} --region {AWS.REGION} | jq -r \'.BootstrapBrokerStringSaslScram\')' >> ~/.bashrc",
                        f"export BOOTSTRAP_SERVERS=$(aws kafka get-bootstrap-brokers --cluster-arn {mskCluster.attr_arn} --region {AWS.REGION} | jq -r \'.BootstrapBrokerStringSaslScram\')",
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
                        "echo 'export API_KEY=PKPBAXYRYGBBDNGOBYV9' >> ~/.bashrc",
                        'export API_KEY=PKPBAXYRYGBBDNGOBYV9',
                        "echo 'export SECRET_KEY=FC4vp8HUkno88tttRMYpONbOBTmcY9lcFXqc5msa' >> ~/.bashrc",
                        'export SECRET_KEY=FC4vp8HUkno88tttRMYpONbOBTmcY9lcFXqc5msa',
                        f"echo 'export BOOTSTRAP_SERVERS=\"$broker_url\"' >> ~/.bashrc",
                        'export BOOTSTRAP_SERVERS=\"$broker_url\"',
                        "echo 'export KAFKA_SASL_MECHANISM=SCRAM-SHA-512' >> ~/.bashrc",
                        'export KAFKA_SASL_MECHANISM=SCRAM-SHA-512',
                        f"echo 'export KAFKA_SASL_USERNAME={parameters.mskClusterUsername}' >> ~/.bashrc",
                        f'export KAFKA_SASL_USERNAME={parameters.mskClusterUsername}',
                        f"echo 'export KAFKA_SASL_PASSWORD={mskClusterPwdParamStoreValue}' >> ~/.bashrc",
                        f'export KAFKA_SASL_PASSWORD={mskClusterPwdParamStoreValue}',
                        "cat ~/.bashrc",
                        "python3 ec2-script-historic.py"
        )