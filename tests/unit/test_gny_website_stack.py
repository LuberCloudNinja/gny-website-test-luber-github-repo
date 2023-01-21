import aws_cdk as core
import aws_cdk.assertions as assertions

from gny_website.gny_website_stack import GnyWebsiteStack

# example tests. To run these tests, uncomment this file along with the example
# resource in gny_website/gny_website_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = GnyWebsiteStack(app, "gny-website")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
