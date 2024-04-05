from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    CfnParameter,
    aws_signer as signer,
    aws_lambda as _lambda,
    aws_s3 as s3
)
from . import parameters
from cdk.cdk_stack import VpcStack

class LambdaStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        bucket = s3.Bucket.from_bucket_name(self, "MyBucket", parameters.bucket_name)

        _lambda.Function(self, "lambdaFunction",
            function_name = f"{parameters.project}-{parameters.env}-{parameters.app}-lambdaFunction",
            runtime = _lambda.Runtime.parameters.lambdaRuntimeVersion,
            handler = parameters.lambdaFunctionHandler,
            timeout = Duration.seconds(30),
            code = _lambda.Code.from_bucket(bucket = bucket,key = "consumerLambdaFunction.zip")
        )
