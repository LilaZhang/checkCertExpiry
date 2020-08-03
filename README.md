<p>A Python AWS Lambda function integrated with CloudWatch Logs, SNS and EventBridge. An automated message will be sent to an endpoint containing the certificates uploaded to ACM expiring in the span of X days. <br> Authored by Lila Zhang</p>

## Console setup
Create a Lambda function via AWS Console with the following: <br>
<ul>
<li>Python 3.6 Environment</li>
<li>A new execution role with basic Lambda permissions</li>
</ul>

### IAM permissions
Ensure the below policies are attached to the newly created execution role:
<ul>
<li>AWSCloudTrailFullAccess</li>
<li>AmazonSNSFullAccess</li>
<li>AWSCertificateManagerFullAccess</li>
</ul>

### Creating a new Event Rule
Set CRON expression *0 6 \* \* ? \** as the schedule.
*This event will be invoked once daily at 6:00 AM.*
<br>Set the Lambda function as the event target.

### Lambda configuration
**triggers**<br>EventBridge<br><br>
**destinations**<br>SNS on-failure<br>
*Any exceptions thrown during runtime will be sent to the specified SNS topic in JSON format.*<br><br>

### gotchas
*TAR_ARN* in the source code is the ARN string of the SNS topic to publish to. Ensure this is replaced with the ARN of the topic
you wish to publish to.

