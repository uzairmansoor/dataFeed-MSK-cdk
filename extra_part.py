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