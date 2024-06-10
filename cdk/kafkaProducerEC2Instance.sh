sudo su
sudo yum update -y
sudo yum -y install java-11
sudo yum install jq -y
wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz
tar -xzf kafka_2.13-3.5.1.tgz
cd kafka_2.13-3.5.1/libs
wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar
cd /home/ec2-user
cat <<EOF > /home/ec2-user/users_jaas.conf
KafkaClient {
    org.apache.kafka.common.security.scram.ScramLoginModule required
    username="${parameters.mskProducerUsername}"
    password="${mskProducerPwdParamStoreValue}";
};
EOF
echo 'export KAFKA_OPTS=-Djava.security.auth.login.config=/home/ec2-user/users_jaas.conf' >> ~/.bashrc
echo 'export BOOTSTRAP_SERVERS=$(aws kafka get-bootstrap-brokers --cluster-arn ${mskCluster.attr_arn} --region ${AWS.REGION} | jq -r \'.BootstrapBrokerStringSaslScram\')' >> ~/.bashrc
echo 'export ZOOKEEPER_CONNECTION=$(aws kafka describe-cluster --cluster-arn ${mskCluster.attr_arn} --region ${AWS.REGION} | jq -r \'.ClusterInfo.ZookeeperConnectString\')' >> ~/.bashrc
aws ssm put-parameter --name ${mskClusterBrokerUrlParamStore.parameter_name} --value "$BOOTSTRAP_SERVERS" --type "${mskClusterBrokerUrlParamStore.parameter_type}" --overwrite --region ${AWS.REGION}
mkdir tmp
cp /usr/lib/jvm/java-11-amazon-corretto.x86_64/lib/security/cacerts /home/ec2-user/tmp/kafka.client.truststore.jks
cat <<EOF > /home/ec2-user/client_sasl.properties
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
ssl.truststore.location=/home/ec2-user/tmp/kafka.client.truststore.jks
EOF
echo 'export AZ_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=${vpc.vpc_id}" --region ${AWS.REGION} | jq -r \'.Subnets[].AvailabilityZoneId\' | tr "\n" ",")' >> ~/.bashrc
export AZ_IDS=$(aws ec2 describe-subnets --filters 'Name=vpc-id,Values=${vpc.vpc_id}' --region ${AWS.REGION} | jq -r '.Subnets[].AvailabilityZoneId' | tr '\n' ',')
aws ssm put-parameter --name ${getAzIdsParamStore.parameter_name} --value "$AZ_IDS" --type "${getAzIdsParamStore.parameter_type}" --overwrite --region ${AWS.REGION}
/kafka_2.13-3.5.1/bin/kafka-acls.sh --authorizer-properties zookeeper.connect=$ZOOKEEPER_CONNECTION --add --allow-principal User:${parameters.mskProducerUsername} --operation Read --topic '*'
/kafka_2.13-3.5.1/bin/kafka-acls.sh --authorizer-properties zookeeper.connect=$ZOOKEEPER_CONNECTION --add --allow-principal User:${parameters.mskProducerUsername} --operation Write --topic '*'
/kafka_2.13-3.5.1/bin/kafka-acls.sh --authorizer-properties zookeeper.connect=$ZOOKEEPER_CONNECTION --add --allow-principal User:${parameters.mskProducerUsername} --operation Read --group '*'
/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic ${parameters.mskTopicName1} --replication-factor 2
/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic ${parameters.mskTopicName2} --replication-factor 2
/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic ${parameters.mskTopicName3} --replication-factor 2
/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --command-config /home/ec2-user/client_sasl.properties --create --topic ${parameters.mskTopicName4} --replication-factor 2
/kafka_2.13-3.5.1/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP_SERVERS --list --command-config ./client_sasl.properties
/kafka_2.13-3.5.1/bin/kafka-acls.sh --authorizer-properties zookeeper.connect=$ZOOKEEPER_CONNECTION --add --allow-principal User:${parameters.mskConsumerUsername} --operation Read --topic=${parameters.mskTopicName3}
/kafka_2.13-3.5.1/bin/kafka-acls.sh --authorizer-properties zookeeper.connect=$ZOOKEEPER_CONNECTION --add --allow-principal User:${parameters.mskConsumerUsername} --operation Read --topic=${parameters.mskTopicName4}
/kafka_2.13-3.5.1/bin/kafka-acls.sh --authorizer-properties zookeeper.connect=$ZOOKEEPER_CONNECTION --add --allow-principal User:${parameters.mskConsumerUsername} --operation Read --group '*'
cd /home/ec2-user
sudo yum update -y
sudo yum install python3 -y
sudo yum install python3-pip -y
sudo mkdir environment
cd environment
sudo yum install python3 virtualenv -y
sudo pip3 install virtualenv
sudo python3 -m virtualenv alpaca-script
source alpaca-script/bin/activate
pip install -r <(aws s3 cp s3://${bucket.bucket_name}/python-scripts/requirement.txt -)
aws s3 cp s3://${bucket.bucket_name}/python-scripts/ec2-script-live.py .
echo 'export API_KEY=PKECLY5H0GVN02PAODUC' >> ~/.bashrc
echo 'export SECRET_KEY=AFHK20nUtVfmiTfuMTUV51OJe4YaQybUSbAs7o02' >> ~/.bashrc
echo 'export KAFKA_SASL_MECHANISM=SCRAM-SHA-512' >> ~/.bashrc
echo 'export KAFKA_SASL_USERNAME=${parameters.mskProducerUsername}' >> ~/.bashrc
echo 'export KAFKA_SASL_PASSWORD=${mskProducerPwdParamStoreValue}' >> ~/.bashrc
