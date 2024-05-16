

import aws_cdk as cdk
import os
from aws_cdk import (
    Aws
)

from cdk.dataFeedMsk import dataFeedMsk
from cdk import parameters

from cdk.dataFeedMskCrossAccount import dataFeedMskCrossAccount

# from cdk.dataFeedMsk_copy import dataFeedMsk
# # from cdk.importMskCluster_copy import importMskCluster
# from cdk import parameters_copy
                                                        
# app = cdk.App()

# aws_env = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])

# dataFeedMsk(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskAwsBlogStack", env=aws_env)

# app.synth()

app = cdk.App()

awsEnvCrossAccount = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])
dataFeedMskCrossAccount(app, f"{parameters.project}-{parameters.env}-{parameters.app}-dataFeedMskCrossAccount", env=awsEnvCrossAccount)

app.synth()

# app = cdk.App()

# aws_env = cdk.Environment(region="us-east-2",account="095773313313")
# # aws_env = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])
# data_feed_msk = dataFeedMsk(app, f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-dataFeedMskAwsBlog", env=aws_env)
# msk_cluster_arn = data_feed_msk.msk_cluster_arn
# import_msk_cluster = importMskCluster(app, f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-importMskCluster", msk_cluster_arn, env=aws_env)

# app.synth()

# app = cdk.App()

# aws_env = cdk.Environment(region="us-east-2",account="095773313313")
# # aws_env = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])
# dataFeedMsk(app, f"{parameters_copy.project}-{parameters_copy.env}-{parameters_copy.app}-dataFeedMskAwsBlogCopy", env=aws_env)

# app.synth()