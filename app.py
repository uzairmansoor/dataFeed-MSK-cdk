

import aws_cdk as cdk

from cdk.cdk_stack import dataFeedMskAwsBlogStack
from cdk.cross_account import dataFeedMskCrossAccountConfig
from cdk import parameters

app = cdk.App()

env = cdk.Environment(region="us-east-1",account="095773313313")
# crossAccountEnv = cdk.Environment(region="us-east-1",account="007756798683")

dataFeedMskAwsBlogStack(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskAwsBlogStack", env=env)

# dataFeedMskCrossAccountConfig(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskCrossAccountConfig", env=crossAccountEnv)

app.synth()
