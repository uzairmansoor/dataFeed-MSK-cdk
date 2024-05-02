

import aws_cdk as cdk
from aws_cdk import Aws
from cdk.dataFeedMsk import dataFeedMsk
# from cdk.dataFeedMskCrossAccount import dataFeedMskCrossAccount
from cdk import parameters

app = cdk.App()

aws_env = cdk.Environment(region="us-east-1",account="095773313313")
# cross_account_aws_env = cdk.Environment(region="us-east-1",account="007756798683")

dataFeedMsk(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskAwsBlogStack", env=aws_env)

# dataFeedMskCrossAccount(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskCrossAccount", env=cross_account_aws_env)

app.synth()
