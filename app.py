

import aws_cdk as cdk
import os
from aws_cdk import (
    Aws
)

from cdk.dataFeedMsk import dataFeedMsk
from cdk import parameters

# from cdk.dataFeedMsk_copy import dataFeedMsk
from cdk.dataFeedMskCrossAccount import dataFeedMskCrossAccount
# from cdk import parameters_copy

app = cdk.App()

aws_env = cdk.Environment(region="us-east-1",account="095773313313")
# aws_env = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])

# aws_env_copy = cdk.Environment(region="us-east-2",account="095773313313")
# cross_account_aws_env = cdk.Environment(region="us-east-1",account="007756798683")

dataFeedMsk(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskAwsBlogStack", env=aws_env)

# dataFeedMsk(app, f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-dataFeedMskAwsBlogCopy", env=aws_env_copy)
# dataFeedMskCrossAccount(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskCrossAccount", env=cross_account_aws_env)

app.synth()
