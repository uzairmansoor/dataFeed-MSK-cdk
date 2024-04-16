project = "awsBlog"
env = "dev"
app = "app"
authorName = "uzair"
cidr_range = "10.20.0.0/16"
no_of_nat_gateways = 3
enable_dns_hostnames = True
enable_dns_support = True
cidrMaskForSubnets = 24
lambdaRuntimeVersion = "PYTHON_3_12"
lambdaTimeout = 30
lambdaFunctionHandler = "consumerLambdaFunction.lambda_handler"
bucket_name = "awsblog-dev-app-us-east-1-095773313313"
bucket_key = "consumerLambdaFunction.zip"
username = "uzair"
password = "Hp^73$d!n"

# MSK Kafka Parameters

mskVersion = "3.5.1"
mskNumberOfBrokerNodes = 2
mskClusterInstanceType = "kafka.m5.large"
mskClusterVolumeSize = 100
mskScramPropertyEnable = True
mskEncryptionClientBroker = "TLS"
mskEncryptionInClusterEnable = True
topic_name = "aws-blog-topic"

# Kafka Client EC2 instance Parameters

instanceClass = "BURSTABLE2"
instanceSize = "LARGE"
keyPairName = "awsBlog-dev-app-us-east-1"
amiName = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20220420"
accountId = "095773313313"
region = "us-east-1"
keyPairType = "RSA"
keyPairFormat = "PEM"

# Flink

apacheFlinkBucketKey = "kinesis-connectors-1.0.jar"
# flinkRuntimeVersion = FLINK_1_11
apacheFlinkAutoScalingEnable = True
apacheFlinkKinesisRegion = "us-east-1"
apacheFlinkKinesisSinkStream = "output-stream"
apacheFlinkKinesisSourceStream = "input-stream"
# flinkAppLogGroupRetentionDays = ONE_WEEK
apacheFlinkParallelism = 1
apacheFlinkParallelismPerKpu = 1
apacheFlinkCheckpointingEnabled = True

# OpenSearch

openSearchVersion = "2.11"
multiAzWithStandByEnabled = False
no_of_master_nodes = 0
no_of_data_nodes = 1
master_node_instance_type = "m5.large.search"
data_node_instance_type = "t3.small.search"
openSearchVolumeSize = 10
openSearchEnableHttps = True
openSearchNodeToNodeEncryption = True
openSearchEncryptionAtRest = True
openSearchMasterUsername = "uzair"
openSearchAvailabilityZoneCount = 2
openSearchAvailabilityZoneEnable = True
