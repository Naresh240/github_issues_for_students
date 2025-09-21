import os
import json
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError
import uuid
import gzip
import urllib.request
import urllib.error

# ---------------------------
# AWS Clients
# ---------------------------
cloudwatch_logs = boto3.client('logs')
cloudwatch = boto3.client('cloudwatch')
ssm = boto3.client('secretsmanager')
s3_client = boto3.client('s3', region_name="us-east-1")
ses = None

# ---------------------------
# Environment Variables
# ---------------------------
region = os.environ['region']
email_dist_list = os.environ['email_dist_list'].split(",")
source_email = os.environ['source_email_address']
application_error_metric_ns = os.environ['application_error_metric_namespace'].split(",")
env = os.environ["environment"]
is_container_restart_enabled = os.environ.get("is_container_restart_enabled", "false")
container_restart_log_stmts = os.environ.get("log_stmt_for_container_restart", "")
container_restart_log_stmts_count = os.environ.get("log_stmt_for_container_restart_max_count", "1")
container_restart_approved_alarm_names = os.environ.get("container_restart_approved_alarm_names", "")
high_priority_log_stmts = os.environ.get("high_priority_log_stmts", "")
high_priority_prefix_text = os.environ.get("high_priority_prefix", "HIGH PRIORITY")
secret_name = os.environ.get("secret_name", "")
download_log_option = os.environ.get("download_log_option", "false")

log_stream = None
approved_alarms_list = container_restart_approved_alarm_names.split('|')

# ---------------------------
# Stored Procedure & EKS Mapping
# ---------------------------
stored_proc_mapping = {
    "preference_data_denormalization_" + env: "usp_preference_data_denormalization",
    "preference_fetch_denormalization_" + env: "usp_preference_data_denormalization_fetch"
}

eks_deployment_mapping = {
    "preference-service": {"namespace": "prod", "deployment": "preference-deployment"},
    "user-service": {"namespace": "prod", "deployment": "user-deployment"}
}

# ---------------------------
# Lambda Handler
# ---------------------------
def lambda_handler(event, context):
    global log_stream
    log_stream = context.log_stream_name
    print("Event received: {}".format(json.dumps(event)))

    message = json.loads(event['Records'][0]['Sns']['Message'])
    namespace = None
    metric_name = None

    # Detect metric structure
    if 'Metrics' in message['Trigger']:
        namespace = message['Trigger']['Metrics'][0]['MetricStat']['Metric']['Namespace']
        metric_name = message['Trigger']['Metrics'][0]['MetricStat']['Metric']['MetricName']
    elif 'Metric' in message['Trigger']:
        namespace = message['Trigger']['Metric']['Namespace']
        metric_name = message['Trigger']['Metric']['MetricName']

    if namespace in application_error_metric_ns:
        response = cloudwatch_logs.describe_metric_filters(
            metricName=metric_name,
            metricNamespace=namespace
        )
        if response['metricFilters']:
            process_metric_data_for_error_logs(message, response)
        else:
            print(f"No metric filters found for {metric_name} in namespace {namespace}")
    elif namespace == 'MariaDB':
        process_metric_data(message)
    else:
        print(f"Metric Namespace {namespace} is not configured for custom emails.")

    return {'statusCode': 200, 'body': json.dumps('Lambda executed successfully')}

# ---------------------------
# Metric Data Processing
# ---------------------------
def process_metric_data(message):
    timestamp = message['StateChangeTime']
    datetimeObj = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f%z')
    offset = message['Trigger']['Period'] * message['Trigger']['EvaluationPeriods']
    start_time = datetimeObj - timedelta(seconds=offset)

    metric_dimensions = message['Trigger'].get('Dimensions', message['Trigger']['Metrics'][0]['MetricStat']['Metric']['Dimensions'])[0]
    dimensions = [{"Name": metric_dimensions["name"], "Value": metric_dimensions["value"]}]
    
    namespace = message['Trigger']['Metric']['Namespace'] if 'Metric' in message['Trigger'] else message['Trigger']['Metrics'][0]['MetricStat']['Metric']['Namespace']
    metric_name = message['Trigger']['Metric']['MetricName'] if 'Metric' in message['Trigger'] else message['Trigger']['Metrics'][0]['MetricStat']['Metric']['MetricName']

    params = {
        'Namespace': namespace,
        'MetricName': metric_name,
        'Dimensions': dimensions,
        'StartTime': start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'EndTime': datetimeObj.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'Period': message['Trigger']['Period'],
        'Statistics': ['SampleCount', 'Average', 'Minimum', 'Maximum']
    }

    print("Metric Statistics Request: {}".format(json.dumps(params, default=str)))
    response = cloudwatch.get_metric_statistics(**params)
    sorted_datapoints = sorted(response['Datapoints'], key=lambda d: d['Timestamp'])
    
    subject = 'Details for Alarm - ' + message['AlarmName']
    alarm_html = get_alarm_table(message)
    metric_html = prepare_email_content(message, sorted_datapoints)
    send_email(subject, alarm_html + metric_html)

# ---------------------------
# Error Log Processing
# ---------------------------
def process_metric_data_for_error_logs(message, response):
    timestamp = message['StateChangeTime']
    datetimeObj = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f%z')
    offset = (message['Trigger']['Period'] * message['Trigger']['EvaluationPeriods']) + 300
    start_time = datetimeObj - timedelta(seconds=offset)
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(datetimeObj.timestamp() * 1000)

    metricFilter = response['metricFilters'][0]
    log_group_name = metricFilter['logGroupName']
    filter_pattern = metricFilter['filterPattern']

    response_fle = cloudwatch_logs.filter_log_events(
        logGroupName=log_group_name,
        startTime=start_ms,
        endTime=end_ms,
        filterPattern=filter_pattern
    )
    if response_fle['events']:
        prepare_email_content_for_error_logs(response_fle, message, log_group_name)
    else:
        print("No log events found!")
        if message['AlarmName'] in approved_alarms_list:
            reset_cw_alarm_state(message['AlarmName'])

# ---------------------------
# Prepare Email Content for Metric
# ---------------------------
def prepare_email_content(message, data):
    style = "<style> pre {color: red;font-family: arial, sans-serif;font-size: 11px;} </style>"
    html = '<br/><b><u>Metric Details:</u></b><br/><br/>' + style

    namespace = message['Trigger']['Metric']['Namespace'] if 'Metric' in message['Trigger'] else message['Trigger']['Metrics'][0]['MetricStat']['Metric']['Namespace']
    metric_name = message['Trigger']['Metric']['MetricName'] if 'Metric' in message['Trigger'] else message['Trigger']['Metrics'][0]['MetricStat']['Metric']['MetricName']

    html += f'<pre><b>Metric Namespace: </b>{namespace}</pre>'
    html += f'<pre><b>Metric Name:</b> {metric_name}</pre>'
    dimension_value = message['Trigger']['Metric']['Dimensions'][0]['value'] if 'Metric' in message['Trigger'] else message['Trigger']['Metrics'][0]['MetricStat']['Metric']['Dimensions'][0]['value']
    html += f'<pre><b>Stored procedure Name: </b>{stored_proc_mapping.get(dimension_value,"NA")}</pre><br>'

    html += "<table border='1' style='font-family: arial, sans-serif;font-size:11px;border-collapse:collapse;width:auto;'>"
    headers = list(data[0].keys())
    html += "<tr>"
    for header in headers:
        html += f"<th style='border:1px solid #ddd;text-align:center;padding:8px;'>{'Record #' if header=='SampleCount' else header}</th>"
    html += "</tr>"

    for row in data:
        html += "<tr>"
        for header in headers:
            val = row[header]
            if header in ['Average', 'Minimum', 'Maximum']:
                val = round(val, 2)
            if header == 'SampleCount':
                val = int(val)
            html += f"<td style='border:1px solid #ddd;text-align:center;padding:8px;'>{val}</td>"
        html += "</tr>"
    html += "</table>"
    html += f"<br><br><br><br><br><u><b>Source Identifier:</b></u> {log_stream}"
    return html

# ---------------------------
# Prepare Email Content for Error Logs
# ---------------------------
def prepare_email_content_for_error_logs(response, message, log_group_name):
    high_priority = False
    events = response['events']
    subject = 'Details for Alarm - ' + message['AlarmName']
    alarm_html = get_alarm_table(message)
    style = "<style> pre {color: red;font-family: arial, sans-serif;font-size: 11px;} </style>"
    log_html = '<br/><b><u>Log Details:</u></b><br/><br/>' + style

    console_url = f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{log_group_name.replace('/', '$252F')}"

    # Table for Pod and Error Message
    log_html += "<table border='1' style='font-family: arial, sans-serif;font-size:11px;border-collapse:collapse;width:100%;'>"
    log_html += "<tr><th style='padding:6px;border:1px solid #ddd;'>Pod Name</th><th style='padding:6px;border:1px solid #ddd;'>Error Message</th></tr>"

    for event in events:
        log_stream_name = event['logStreamName']
        try:
            msg = json.loads(event['message'])
            pod_name = msg.get("podName", log_stream_name)
            error_msg = msg.get("logMessage", json.dumps(msg))
        except Exception:
            pod_name = log_stream_name
            error_msg = event['message']

        log_html += f"<tr><td style='padding:6px;border:1px solid #ddd;'>{pod_name}</td><td style='padding:6px;border:1px solid #ddd;'>{error_msg}</td></tr>"

    log_html += "</table><br/>"

    if is_container_restart_enabled.lower() == "true" and message['AlarmName'] in approved_alarms_list:
        high_priority, matched_events = check_events_for_los_stmts(events)
        if len(matched_events) >= int(container_restart_log_stmts_count):
            restarted_ids = restart_containers_eks(matched_events)
            restart_html = '<br/><b><u>Restarted Containers (EKS Deployments):</u></b><br/>' + style + '<pre>'
            if restarted_ids:
                restart_html += '<ol>'
                for cid in restarted_ids:
                    restart_html += f"<li><b>{cid}</b></li>"
                restart_html += '</ol>'
            restart_html += '</pre>'
            log_html = restart_html + log_html

    if high_priority:
        subject = f"{high_priority_prefix_text}: {subject}"

    send_email(subject, alarm_html + log_html)

# ---------------------------
# Check Log Events for Restart/High Priority
# ---------------------------
def check_events_for_los_stmts(events):
    high_priority = False
    container_restart_events = []
    log_stmts = container_restart_log_stmts.split('|')
    high_priority_stmts = high_priority_log_stmts.split('|')

    for event in events:
        try:
            msg = json.loads(event['message'])
            if any(s in msg.get('logMessage','') for s in log_stmts):
                container_restart_events.append(msg)
            if any(s in msg.get('logMessage','') for s in high_priority_stmts):
                high_priority = True
        except Exception as e:
            print(f"Error parsing log event: {e}")

    return high_priority, container_restart_events

# ---------------------------
# Restart EKS Deployments
# ---------------------------
def restart_containers_eks(matched_log_events):
    restarted_deployments = []
    kube_api_url = "https://ucc-dm.est.k8s.dev.dm.aws.spctrm.net"
    api_token = get_api_token(secret_name, region)
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/strategic-merge-patch+json"}

    for event in matched_log_events:
        container_name = event.get('env', {}).get('containerName')
        if container_name in eks_deployment_mapping:
            dep_info = eks_deployment_mapping[container_name]
            patch_body = {"spec": {"template": {"metadata": {"annotations": {"restartedAt": str(datetime.utcnow())}}}}}
            url = f"{kube_api_url}/apis/apps/v1/namespaces/{dep_info['namespace']}/deployments/{dep_info['deployment']}"
            req = urllib.request.Request(url, method='PATCH', headers=headers, data=json.dumps(patch_body).encode())
            try:
                with urllib.request.urlopen(req) as resp:
                    print(f"Deployment {dep_info['deployment']} restarted: {resp.read().decode()}")
                    restarted_deployments.append(container_name)
            except urllib.error.HTTPError as e:
                print(f"Error restarting deployment {dep_info['deployment']}: {e.read().decode()}")

    return restarted_deployments

# ---------------------------
# Fetch API_TOKEN from Secrets Manager
# ---------------------------
def get_api_token(secret_name, region):
    try:
        response = ssm.get_secret_value(SecretId=secret_name)
        secret = json.loads(response['SecretString'])
        return secret['API_TOKEN']
    except Exception as e:
        print(f"Error retrieving API_TOKEN from secrets manager: {e}")
        return None

# ---------------------------
# Reset CloudWatch Alarm
# ---------------------------
def reset_cw_alarm_state(alarm_name):
    try:
        client = boto3.client('cloudwatch', region_name=region)
        response = client.describe_alarms(AlarmNames=[alarm_name])
        state = response['MetricAlarms'][0]['StateValue']
        if state != "OK":
            client.set_alarm_state(
                AlarmName=alarm_name,
                StateValue='OK',
                StateReason='Set manually after executing Lambda at ' + str(datetime.utcnow())
            )
            print(f"Alarm {alarm_name} reset to OK")
    except Exception as e:
        print(f"Error resetting alarm {alarm_name}: {e}")

# ---------------------------
# SES Email
# ---------------------------
def send_email(subject, html_content):
    global ses
    if ses is None:
        ses = boto3.client('ses', region_name=region)
    try:
        ses.send_email(
            Source=source_email,
            Destination={'BccAddresses': email_dist_list},
            Message={'Subject': {'Data': subject}, 'Body': {'Html': {'Data': html_content}}}
        )
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {e}")

# ---------------------------
# Alarm Table HTML
# ---------------------------
def get_alarm_table(message):
    timestamp = message['StateChangeTime']
    datetimeObj = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f%z')
    description = message.get('AlarmDescription', 'Not Available')

    table_html = "<table border='1' style='font-family:arial,sans-serif;font-size:11px;border-collapse:collapse;width:auto;'>"
    table_html += f"<tr><td><b>Alarm Name</b></td><td>{message['AlarmName']}</td></tr>"
    table_html += f"<tr><td><b>Alarm Description</b></td><td>{description}</td></tr>"
    table_html += f"<tr><td><b>Alarm Time</b></td><td>{datetimeObj.strftime('%d-%m-%Y %H:%M:%S')} UTC</td></tr>"
    table_html += f"<tr><td><b>AWS Region</b></td><td>{message['Region']}</td></tr>"
    table_html += f"<tr><td><b>AWS Account ID</b></td><td>{message['AWSAccountId']}</td></tr>"
    table_html += "</table>"
    return table_html
