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
bucket_name = "awsblog-dev-app-us-east-1-007756798683"
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
accountId = "007756798683"
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