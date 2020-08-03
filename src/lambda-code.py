import json
import boto3
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta

# Span of days to check for certificate expiry
DAYS_EXP = 30

# Interval of time to check for expiration (in datetime)
time_interval = datetime.now(timezone.utc) + timedelta(days=DAYS_EXP)

# Target ARN of SNS topic to publish to
TAR_ARN = 'a-valid-sns-arn'

# Name of AWS account certifcates are stored in
ACC = 'a-valid-aws-account'

# Tokens to extract in response
SEARCH_TOKEN = {
    'status': 'ISSUED',
    'summary': 'CertificateSummaryList',
    'arn': 'CertificateArn',
    'cert': 'Certificate',
    'expiry': 'NotAfter'
}

def default_value() -> str:
    """
    Default value for keys not present in the dictionary
    :return: A default string for non-existing keys
    """
    return 'Key Not Found'

def set_logging_format(log_format: str, date_format: str) -> None:
    """
    Formats logging output and attached timestamp
    :param log_format: A string specifying log output
    :param date_format: A string specifyin date output
    """
    logging.basicConfig(format=log_format, datefmt=date_format)

def get_certificate_summary(acm_client: object) -> dict:
    """
    Retrieves all certificate details from the ACM client
    :param acm_client: ACM client
    :return: A dict of response metadata as a dictionary
    """
    response = acm_client.list_certificates(CertificateStatuses=[SEARCH_TOKEN['status']])
    # Extract summary list from response
    return response[SEARCH_TOKEN['summary']]

def get_all_certificates(acm_client: object) -> defaultdict:
    """
    Initialises a list of certificate ARNS from ACM and populates a record of each certificate's ARN and
    corresponding expiry date.
    :param acm_client: ACM client
    :return: A defaultdict of unique certificate ARNs
    """
    summary_list = get_certificate_summary(acm_client)
    certs = defaultdict(default_value)

    for s in summary_list:
        arn = s[SEARCH_TOKEN['arn']]
        details = acm_client.describe_certificate(CertificateArn=arn)
        cert = details[SEARCH_TOKEN['cert']]
        # Keys: Certificate, ResponseMetadata
        key = cert[SEARCH_TOKEN['arn']]
        val = cert[SEARCH_TOKEN['expiry']]
        certs[key] = val
    return certs

def get_expired_certificates(acm_client: object, logger: logging) -> defaultdict:
    """
    Retrieves all expired certificates from the ACM client based on specified span of days.
    :param acm_client: ACM client
    :param logger: Logging object
    :return: A defaultdict of keys
    """
    # defaultdict of all certificate ARNs and expiry dates
    certs = get_all_certificates(acm_client)
    expired_certs = defaultdict(default_value)
    for arn in certs:
        # Expiry datetime is certs[arn]
        # Compare expiry datetime with current date
        if (bool(certs) and certs[arn] != default_value):
            expiry_date = certs[arn]
        # Logs true if a certificate wil expire in specified number of days
        logger.info(f'Certificate will expire in {DAYS_EXP} days:{time_interval >= expiry_date}')
        if (time_interval) >= expiry_date:
            expired_certs[arn] = expiry_date
        else:
            logger.info(f'Certificate {arn} is still valid. The expiry date is {expiry_date}')
    return expired_certs

def build_message(acm_client: object, logger: logging) -> str:
    """
    Outputs a status message as a string.
    :param acm_client: ACM client
    :param logger: Logging object
    :return: A string message
    """
    # Expired certificates
    expired_certs = get_expired_certificates(acm_client, logger)
    message = ''
    if (expired_certs):
        # Final message passed to the SNS topic
        message = 'The following certificates uploaded to AWS Certificate Manager on account {} will expire in {} days.\n\n'.format(ACC, str(DAYS_EXP))
        message_arns = ''
        for arn, exp_dt in expired_certs.items():
            tmp = arn + '\nExpiry date: {}\n\n'.format(str(exp_dt))
            message_arns += tmp
        
        message += message_arns
        return message

def lambda_handler(event, context):
    # ACM client will retrieve the expiry date of each certificate
    # SNS client sends messages to topic
    acm_client = boto3.client('acm')
    sns_client = boto3.client('sns')

    # Configure logging
    set_logging_format('%(asctime)s-%(message)', '%d-%b-%y %H:%M:%S')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    message = build_message(acm_client, logger)
    if (len(message) > 0):
        try:
            sns_resp = sns_client.publish(
                TargetArn=TAR_ARN,
                Message=message,
                MessageStructure='string'
            )
        except Exception as e:
            logger.info(f'Exception {e} thrown when attempting to publish message to {TAR_ARN}.')
            sns_resp = 'Unable to publish message.'
        logger.info(json.dumps(sns_resp))
