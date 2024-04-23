

import aws_cdk as cdk

from cdk.cdk_stack import dataFeedMskAwsBlogStack
from cdk import parameters

app = cdk.App()

env = cdk.Environment(region="us-east-1",account="095773313313")

dataFeedMskAwsBlogStack(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskAwsBlogStack", env=env)

app.synth()
