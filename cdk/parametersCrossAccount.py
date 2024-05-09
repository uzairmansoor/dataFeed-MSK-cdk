project = "awsblog"             #Project name
env = "qa"                      #Environment name
app = "app"                     #App name

###   VPC Parameters   ###

cidrRange = "10.20.0.0/16"      #IPv4 CIDR range for VPC
numberOfNatGateways = 2         #Number of NAT Gateways
enableDnsHostnames = True       #Specify whether to enable or disable DNS support for VPC
enableDnsSupport = True         #Specify whether to enable or disable DNS hostnames
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
sourceBucketName = "kafka-flink-blog-bucket"

###   Secrets Manager Parameters   ###

mskClusterUsername = "uzair"        #Username for MSK Cluster

###   MSK Kafka Parameters   ###

mskClusterArn = "arn:aws:kafka:us-east-1:095773313313:cluster/awsblog-dev-app-mskCluster/69607437-28c7-4dcf-bde7-2c6cfd521bd1-24"
mskClusterName = f'{project}-{env}-{app}-mskCluster'

mskVersion = "3.5.1"                        #Version of MSK cluster
mskNumberOfBrokerNodes = 2                  #Number of broker nodes of an MSK Cluster
mskClusterInstanceType = "kafka.m5.large"   #Instance type of MSK cluster
mskClusterVolumeSize = 100                  #Volume Size of MSK Cluster
mskScramPropertyEnable = True               #Enable SCRAM (SASL/SCRAM) property for MSK Cluster
mskEncryptionClientBroker = "TLS"           #Encryption protocol used for communication between clients and 
                                            #brokers in MSK Cluster
mskEncryptionInClusterEnable = True         #Enable Encryption in MSK Cluster
mskTopicName1 = "googl"                     #Name of the first MSK topic
mskTopicName2 = "tesl"                      #Name of the second MSK topic
mskCrossAccountId = "007756798683"          #Cross Account ID for MSK

###   MSK Client EC2 Instance Parameters   ### 

ec2InstanceClass = "BURSTABLE2"             #Instance class for EC2 instances
ec2InstanceSize = "MICRO"                   #Size of the EC2 instance
ec2AmiName = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20220420"   #AMI name for EC2 instances

###   Apache Flink Parameters   ###

apacheFlinkBucketKey = "flink-app-1.0.jar"  #Key for accessing the Apache Flink bucket
apacheFlinkRuntimeVersion = "FLINK-1_18"    #Runtime version of Apache Flink
apacheFlinkAutoScalingEnable = True         #Enable auto-scaling for Apache Flink
apacheFlinkParallelism = 1                  #Parallelism degree for Apache Flink
apacheFlinkParallelismPerKpu = 1            #Parallelism degree per KPU (Kinesis Processing Unit) for Apache Flink
apacheFlinkCheckpointingEnabled = True      #Enable checkpointing for Apache Flink

###   OpenSearch Parameters   ###

openSearchVersion = "2.11"                          #Version of OpenSearch
openSearchMultiAzWithStandByEnable = False          #Enable multi-AZ deployment with standby for OpenSearch                
openSearchDataNodes = 1                             #Number of data nodes in OpenSearch cluster   
openSearchDataNodeInstanceType = "t3.small.search"  #Instance type for OpenSearch data nodes
openSearchVolumeSize = 10                           #Volume size for OpenSearch data nodes
openSearchNodeToNodeEncryption = True               #Enable node-to-node encryption for OpenSearch
openSearchEncryptionAtRest = True                   #Enable encryption at rest for OpenSearch
openSearchMasterUsername = "uzair"                  #Username for accessing OpenSearch
openSearchAvailabilityZoneCount = 2                 #Number of AZs for OpenSearch deployment
openSearchAvailabilityZoneEnable = True             #Enable deployment of OpenSearch across multiple AZs                 
eventTickerIntervalMinutes = "1"                    #Interval in minutes for event ticker