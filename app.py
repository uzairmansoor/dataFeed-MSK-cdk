#!/usr/bin/env python3

import aws_cdk as cdk

from cdk.cdk_stack import dataFeedMskAwsBlogStack
# from cdk.lambda_function import LambdaStack
from cdk import parameters

app = cdk.App()

env = cdk.Environment(region="us-east-1",account="007756798683")

dataFeedMskAwsBlogStack(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskAwsBlogStack", env=env)#f"{parameters.project}-{parameters.env}-{parameters.app}-vpc"
# LambdaStack(app, "LambdaStack")#f"{parameters.project}-{parameters.env}-{parameters.app}-lambdaFunction"

app.synth()
