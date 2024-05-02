from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    CfnParameter,
    aws_signer as signer,
    aws_lambda as _lambda,
    aws_s3 as s3
)
from . import parameters_test1
from cdk.cdk_test1 import VpcStack

class LambdaStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        bucket = s3.Bucket.from_bucket_name(self, "MyBucket", parameters_test1.bucket_name)

        _lambda.Function(self, "lambdaFunction",
            function_name = f"{parameters_test1.project}-{parameters_test1.env}-{parameters_test1.app}-lambdaFunction",
            runtime = _lambda.Runtime.parameters.lambdaRuntimeVersion,
            handler = parameters_test1.lambdaFunctionHandler,
            timeout = Duration.seconds(30),
            code = _lambda.Code.from_bucket(bucket = bucket,key = "consumerLambdaFunction.zip")
        )
