# Real-Time Financial Data Feeds with Amazon MSK, Apache Flink, and Amazon OpenSearch
Overview
This project demonstrates how to set up a real-time financial data feed pipeline using Amazon Managed Streaming for Apache Kafka (MSK), Apache Flink, and Amazon OpenSearch. The pipeline processes raw financial data, enriches it, and makes it available for querying. Additionally, a Kafka client running on an EC2 instance in a separate VPC consumes the enriched data feed.

![alt text](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/df738eac-f764-4f9f-8106-db1027de3cbb)

Architecture
Amazon MSK Cluster: Hosts the Kafka topics for raw and enriched data feeds.
Apache Flink Application: Processes and enriches the raw data.
Amazon OpenSearch: Stores the enriched data for querying.
EC2 Instance in a Separate VPC: Runs a Kafka client that consumes the enriched data feed.
Prerequisites
AWS Account
AWS CLI configured
Terraform installed (optional, for infrastructure as code)
Apache Flink knowledge
Kafka client knowledge

Deploying the Infrastructure   

  

On your development machine, clone the repo and install the Python packages.  

git clone https://git-codecommit.us-east-1.amazonaws.com/v1/repos/dataFeedMsk-awsBlog-repo-us-east-1  

Setup the AWS CLI credentials of your client AWS Account  

cd dataFeedMsk-awsBlog-repo-us-east-1  

python3 –m pip install –r requirements.txt  

set CDK_DEFAULT_ACCOUNT=123456789012  

set CDK_DEFAULT_REGION=us-east-1  

cdk bootstrap aws://ACCOUNT-NUMBER/REGION  

Once bootstrapped, the configuration of the "CDK Toolkit" stack will be displayed as follows within the Cloud Formation console. 

![alt text](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/786871c1-0dea-499e-a79d-7761adfe3905)

This step will create a new provider VPC and launch the Amazon MSK cluster there. It also deploys the Apache Flink application, OpenSearch domain and launches a new EC2 instance to run the application that fetches the raw stock quotes.  

Make sure that the enableSaslScramClientAuth, enableClusterConfig, and enableClusterPolicy parameters in the parameters.py file is set to False.  

Update the mskCrossAccountId parameter in the parameters.py file with your AWS cross-account ID.  

cdk deploy --all --app "python app1.py" --profile PROFILE-NAME 

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/cd40f406-22f3-415a-9604-5162e9009980)

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/21c46f43-93e5-42b1-a6f2-9936cd1bb5a6)

NOTE: This step can take up to 45-60 minutes. 
4.	Now, set the enableSaslScramClientAuth, enableClusterConfig, and enableClusterPolicy parameters in the parameters.py file to True. 
 
This step will enable the SASL/SCRAM client authentication, Cluster configuration and PrivateLink.
 cdk deploy --all --app "python app2.py" --profile PROFILE-NAME

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/2ee3b88f-e912-4db4-83f7-f4624668dd10)

Before deploying the cross-account stack, we need to modify some parameters in the parameters.py file. 
•	Copy the MSK Cluster ARN and update the “mskClusterArn” parameter. 

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/5afea7e3-ab01-4fe7-addf-6c8c9845aa59)

•	If you haven't changed the name of the MSK cluster, there's no need to update the “mskClusterName” parameter. If you have, update it with your own MSK Cluster name. 
•	Go to the Systems Manager Parameter Store through the console, copy the value of the “blogAws-dev-mskCustomerPwd-ssmParamStore” parameter, and update the “mskCustomerPwdParamStoreValue” parameter in the parameters.py file. 
5.	Setup the AWS CLI credentials of your customer AWS Account 
set CDK_DEFAULT_ACCOUNT=123456789012 
set CDK_DEFAULT_REGION=us-east-1 
cdk bootstrap aws://ACCOUNT-NUMBER/REGION 
Once bootstrapped, the configuration of the "CDK Toolkit" stack will be displayed as follows within the Cloud Formation console.

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/4ed93c99-b4f9-4c8a-8537-038d86b9cf88)

In the final iteration, we will deploy the cross-account resources, which include the VPC, Security Groups, IAM Roles, and MSK Cluster VPC Connection.

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/e35c0917-e66c-4469-8c1c-ca258b9e0364)

![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/85d6216b-14b2-458b-afea-009aa9f9c71c)

Now that we have the infrastructure up and ready we produce from the Producer ec2 to the MSK, enrich it using Apache flink and consumer it cross account using private link. 
1. Using Flink application:
1.	Navigate to your flink application dashboard 
2.	And bring the application into running state by click run
 
 ![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/cbabea59-4c1b-4a36-90fe-796b1ab2bb14)

3.	Navigate to open Apache flink dashboard, and the application should have a job running 
 
![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/0bd0c45d-4b64-4471-bc1e-bb86de8fb398)

2. Using producer Ec2:
Export the following commands after connecting to the ec2
1.	sudo su
2.	cd environment
3.	source alpaca-script/bin/activate 
4.	Export the following environment variables API_KEY, SECRET_KEY, BOOTSTRAP_SERVERS, KAFKA_SASL_MECHANISM, KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD
5.	To run the script, use command python3 ec2-live-script.py <arg1> <arg2>......<arg n>
example: python3 ec2-live-script.py TSLA GOOGL

 ![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/e92dbdb1-667e-49a7-bb53-1630e7767e42)

3. Using OpenSearch:
1.	Navigate to your OpenSearch dashboard and sign in using your master username and password
2.	Navigate to index management and then indices, you can find the indexes created  

 ![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/83fe9c84-08ab-4077-9a9d-5891b68e7113)

3.	To further explore the data, we can create index pattern by going to the dashboard management and creating index pattern. Navigate to discover and you can see the data with the index pattern created 
 
![image](https://github.com/uzairmansoor/dataFeed-MSK-cdk/assets/82077348/7558dced-2ed6-4e04-94c7-636f099bb114)

  4. Cross account data consumption:
1.	Customer can consume the data cross account by running the following command on the ec2 

<path-to-your-kafka-installation>/bin/kafka-console-consumer.sh --bootstrap-server {$MULTI_VPC_BROKER_URL} --topic googlenhanced --from-beginning --consumer.config ./customer_sasl.properties
