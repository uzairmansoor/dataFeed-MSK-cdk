# Publishing real-time financial data feeds using Amazon Managed Streaming for Kafka

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/f7f19884-9d49-4f70-8246-8cdb8356380d)

## Prerequisites

To deploy this solution, you need to do the following: 
 
•	[Create an AWS account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html) if you do not already have one and log in. Then create an IAM user with full admin permissions as described at [Create an Administrator](https://docs.aws.amazon.com/streams/latest/dev/setting-up.html) User. Log out and log back into the AWS console as this IAM admin user.

**NOTE:** Ensure you have two AWS accounts to proceed with this blog.

**NOTE**: This entire setup may take up to 1 hour and 30 minutes.

•	Install the AWS Command Line Interface (AWS CLI) on your local development machine and create a profile for the admin user as described at [Set Up the AWS CLI](https://docs.aws.amazon.com/streams/latest/dev/setup-awscli.html).   

•	Create a Key Pair named “*awsBlog-dev-app-us-east-1*” in both accounts to enable connections for our producer and consumer EC2 instances. If you change the Key Pair's name, ensure you update the “keyPairName” parameter in the *parameters.py* file located at
“*dataFeedMsk\dataFeedMsk\parameters.py*”.

•	Install the latest version of AWS CDK globally

*npm install -g aws-cdk@latest*

## Infrastructure Automation
 
AWS CDK is used to develop parameterized scripts for building the necessary infrastructure. These scripts include various services required for the infrastructure setup.
 
1.	Amazon VPC and Security Groups
2.	KMS Keys
3.	Secrets Manager
4.	SSM Parameter Stores
5.	CloudWatch Log Groups
6.	MSK Cluster
7.	IAM Roles
8.	EC2 Instances
9.	OpenSearch Domain
10.	Apache Flink Application

## Deploying the Infrastructure 
 
1.	On your development machine, clone the repo and install the Python packages.

*git clone {public_repository_url}*

2.	Install the necessary libraries

*cd dataFeedMSK*

*pip install –r requirements.txt* [**Run this command in Powershell**]

3.	Set the environment variables

*set CDK_DEFAULT_ACCOUNT={your_aws_account_id}*

*set CDK_DEFAULT_REGION=us-east-1*

4.	Bootstrap the first AWS environment (**Producer AWS Account**)

*cdk bootstrap aws://{your_aws_account_id}/{your_aws_region}* [**Run this command in CMD**]	

5.	Once bootstrapped, the configuration of the "**CDK Toolkit**" stack will be displayed as follows within the Cloud Formation console.

![cdk_tool_kit](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/5d6d0b40-7c29-4f0d-8af3-1b9fb896f8f3)

3.	This step involves creating a VPC and deploying the Amazon MSK cluster within it. Additionally, it sets up an Apache Flink application, establishes an OpenSearch domain, and launches a new EC2 instance to handle the retrieval of raw exchange data.

•	Make sure that the *enableSaslScramClientAuth*, *enableClusterConfig*, and *enableClusterPolicy* parameters in the *parameters.py* file are set to False.

•	Update the mskCrossAccountId parameter in the *parameters.py* file with your AWS cross-account ID.

Make sure you are in the directory where the app1.py file is located.: *dataFeedMsk\*

*cdk deploy --all --app "python app1.py" --profile {your_profile_name}*

![cfn_resources](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/d4b88398-32ea-4719-87fc-b5299f041642)

![cfn_resources_1](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/35dfe8ab-e0ba-43f9-92f0-f14030b09b59)

**NOTE**: This step can take up to 45-60 minutes.

4. This deployment creates an S3 bucket to store the solution artifacts, which include the Flink application JAR file, Python scripts, and user data for both the producer and consumer.

![bucket1](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/81459024-5557-4f50-a8e6-8ad0f626715c)

![bucket2](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/d4bb6283-0f38-4e06-9779-edd7fbaf084f)

![bucket3](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/de60279e-b60c-4f0a-9ae3-d4b1e04138ec)

5.	Now, set the *enableSaslScramClientAuth*, *enableClusterConfig*, and *enableClusterPolicy* parameters in the *parameters.py* file to True. 
 
This step will enable the SASL/SCRAM client authentication, Cluster configuration and PrivateLink.

Make sure you are in the directory where the app1.py file is located.: *dataFeedMsk\*

*cdk deploy --all --app "python app1.py" --profile {your_profile_name}*

**NOTE**: This step can take up to 30 minutes.

![msk_cluster](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/d28e34a4-c870-4c0d-bf57-367d0e7581c3)

**Note:** Below are the steps to configure the infrastructure in the second account

Before deploying the cross-account stack, we need to modify some parameters in the *parameters.py* file.

•	Log in to the AWS Management Console and navigate to MSK.

•	Copy the MSK Cluster ARN and update the “**mskClusterArn**” parameter value in the *parameters.py* file. 

![msk_cluster_2](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/5581dcfe-2039-45ab-9fbf-6b8a2c2317ea)

•	If you haven't changed the name of the MSK cluster, there's no need to update the “**mskClusterName**” parameter. If you have, update it with your own MSK Cluster name.

•	Now navigate to Systems Manager (SSM) Parameter Store.

•	Copy the value of the “**blogAws-dev-mskConsumerPwd-ssmParamStore**” parameter, and update the “**mskConsumerPwdParamStoreValue**” parameter in the *parameters.py* file.

•	Then, check the value of the parameter named "**getAzIdsParamStore**" and make a note of these two values.

•	Switch to your second AWS account (Consumer Account) and go to the Resource Access Manager (RAM) service through the console.

•	In the RAM console, click on "**Resource Access Manager**" at the top left of the page.

![ram](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/f07d4133-62a6-4755-b6a2-69d68cbee827)

•	At the bottom right, you will see a table listing AZ Names and AZ IDs.

![ram_1](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/16af7e28-6af1-441e-9fbe-43dcc79fbf58)

•	Compare the AZ IDs from the SSM parameter store with the AZ IDs in this table.

•	Identify the corresponding AZ Names for the matching AZ IDs.

•	Open the *parameters.py* file and insert these AZ Names into the variables “*crossAccountAz1*” and “*crossAccountAz2*”.

![ram_2](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/1bb3b341-b825-4069-b3f0-3b10047a0eae)

For example, in the SSM Parameter Store, the values are "use1-az4" and "use1-az6". When you switch to the second account's RAM and compare, you find that these values correspond to the AZ names "us-east-1a" and "us-east-1b". You need to update the *parameters.py* file with these AZ names by setting crossAccountAz1 to "us-east-1a" and crossAccountAz2 to "us-east-1b".

Note: Ensure that the Availability Zone IDs for both of your accounts are the same.

1.	Now, setup the AWS CLI credentials of your consumer AWS Account Set the environment variables

*set CDK_DEFAULT_ACCOUNT={your_aws_account_id}*

*set CDK_DEFAULT_REGION=us-east-1*

2.	Bootstrap the first AWS environment (Consumer AWS Account)

*cdk bootstrap aws://{your_aws_account_id}/{your_aws_region}* [**Run this command in CMD**]

Once bootstrapped, the configuration of the "CDK Toolkit" stack will be displayed as follows within the Cloud Formation console.

![cross_account_cdk](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/092e0c00-a0e3-48ce-bfdc-9b0f1c929798)

3.	In the final iteration, we will deploy the cross-account resources, which include the VPC, Security Groups, IAM Roles, and MSK Cluster VPC Connection.

Make sure you are in the directory where the app2.py file is located.: *dataFeedMsk\*

*cdk deploy --all --app "python app2.py" --profile {your_profile_name}*

![cross_account_cfn](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/61297eb5-ae09-4b65-a7cc-3662e27b4933)

![vpc_connection](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/80d9b43b-0966-4a80-b473-3e280689b609)
