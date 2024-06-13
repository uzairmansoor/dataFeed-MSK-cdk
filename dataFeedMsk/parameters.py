project = "awsblog"             #Project name
env = "dev"                     #Environment name dev,prod,stag
app = "app"                     #App name

###   VPC Parameters   ###

cidrRange = "10.20.0.0/16"      #IPv4 CIDR range for VPC
numberOfNatGateways = 2         #Number of NAT Gateways
enableDnsHostnames = True       #Specify True to enable DNS support for VPC otherwise False
enableDnsSupport = True         #Specify True to enable DNS hostnames for VPC otherwise False
az1 = "us-east-1a"              #Availability Zone ID
az2 = "us-east-1b"              #Availability Zone ID
cidrMaskForSubnets = 24         #IPv4 CIDR Mask for Subnets

###   EC2 Key Pair Parameters   ###

keyPairName = "awsBlog-dev-app-us-east-1"       #EC2 Key pair name

###   Security Group Parameters   ###

sgMskClusterInboundPort = 0                 #Inbound Port for MSK Cluster Security Group
sgMskClusterOutboundPort = 65535            #Outbound Port for MSK Cluster Security Group
sgKafkaInboundPort = 9092                   #Inbound Port for MSK Cluster Security Group from EC2 Kafka Producer
sgKafkaOutboundPort = 9098                  #Outbound Port for MSK Cluster Security Group from EC2 Kafka Producer
crossAccountVpcCidrRange = "10.20.0.0/16"   #Cross Account IPv4 CIDR range for VPC

###   S3 Bucket Parameters   ###

s3BucketName = "awsblog-dev-app-us-east-1-095773313313"     #Name of S3 Bucket for Storing Code and Artifacts

###   Secrets Manager Parameters   ###

mskProducerUsername = "netsol"        #Producer username for MSK 
mskConsumerUsername = "consumer"      #Consumer username for MSK

###   MSK Kafka Parameters   ###

mskVersion = "3.5.1"                        #Version of MSK cluster
mskNumberOfBrokerNodes = 2                  #Number of broker nodes of an MSK Cluster
mskClusterInstanceType = "kafka.m5.large"   #Instance type of MSK cluster
mskClusterVolumeSize = 100                  #Volume Size of MSK Cluster
mskScramPropertyEnable = True               #Select True to enable (SASL/SCRAM) property for MSK Cluster otherwise False
mskEncryptionProducerBroker = "TLS"         #Encryption protocol used for communication between producer and brokers in MSK Cluster
mskEncryptionInClusterEnable = True         #Select True to enable encryption in MSK Cluster otherwise False
mskTopicName1 = "googl"                     #Name of the first MSK topic
mskTopicName2 = "tsla"                      #Name of the second MSK topic
mskTopicName3 = "googlenhanced"             #Name of the third MSK topic
mskTopicName4 = "teslenhanced"              #Name of the fourth MSK topic
mskCrossAccountId = "576737476547"          #Cross Account ID for MSK

###   MSK Producer EC2 Instance Parameters   ### 

ec2InstanceClass = "BURSTABLE2"             #Instance class for EC2 instances
ec2InstanceSize = "LARGE"                   #Size of the EC2 instance
ec2AmiName = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20220420"   #AMI name for EC2 instances

###   Apache Flink Parameters   ###

apacheFlinkBucketKey = "flink-app-1.0.jar"  #Key for accessing the Apache Flink bucket
apacheFlinkRuntimeVersion = "FLINK-1_18"    #Runtime version of Apache Flink
apacheFlinkAutoScalingEnable = True         #Select True to enable auto-scaling for Apache Flink otherwise False
apacheFlinkParallelism = 1                  #Parallelism degree for Apache Flink
apacheFlinkParallelismPerKpu = 1            #Parallelism degree per KPU (Kinesis Processing Unit) for Apache Flink
apacheFlinkCheckpointingEnabled = True      #Select True to enable checkpointing for Apache Flink otherwise False

###   OpenSearch Parameters   ###

openSearchVersion = "2.11"                          #Version of OpenSearch
openSearchMultiAzWithStandByEnable = False          #Select True to enable multi-AZ deployment with standby for OpenSearch otherwise False               
openSearchDataNodes = 1                             #Number of data nodes in OpenSearch cluster   
openSearchDataNodeInstanceType = "t3.small.search"  #Instance type for OpenSearch data nodes
openSearchVolumeSize = 10                           #Volume size for OpenSearch data nodes
openSearchNodeToNodeEncryption = True               #Select True to enable node-to-node encryption for OpenSearch otherwise False
openSearchEncryptionAtRest = True                   #Select True to enable encryption at rest for OpenSearch otherwise False
openSearchMasterUsername = "opensearch"                  #Username for accessing OpenSearch
openSearchAvailabilityZoneCount = 2                 #Number of AZs for OpenSearch deployment
openSearchAvailabilityZoneEnable = True             #Select True to enable deployment of OpenSearch across multiple AZs otherwise False                 
eventTickerIntervalMinutes = "1"                    #Interval in minutes for event ticker

###   userInput   ###
enableSaslScramClientAuth = False     #In the first iteration, disable SASL/SCRAM client authentication, and in the second iteration, enable it.
enableClusterConfig = False             #In the first iteration, disable cluster configuration, and in the second iteration, enable it
enableClusterPolicy = False             #In the first iteration, disable cluster policy, and in the second iteration, enable it

###     Cross Account Parameters    ###

mskClusterArn = "arn:aws:kafka:us-east-1:546268160168:cluster/awsblog-dev-app-mskCluster/d0e3f2cf-6e6a-4ad0-b1f2-864a9c8cb62d-21"   #ARN of the MSK cluster
mskClusterName = f'{project}-{env}-{app}-mskCluster'                    #Name of the MSK cluster
mskConsumerPwdParamStoreValue = "m1cMuWhg8V2AfOYb6I1RkF4totHCl4He"      #Password stored in AWS Parameter Store for MSK consumer
crossAccountAz1 = "us-east-1c"                                          #Availability Zone 1 for cross-account deployment
crossAccountAz2 = "us-east-1d"                                          #Availability Zone 2 for cross-account deployment