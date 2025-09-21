import os
import json
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError
import uuid
import gzip
import urllib.request
import urllib.error
import html

# ---------------------------
# AWS Clients
# ---------------------------
cloudwatch_logs = boto3.client('logs')
cloudwatch = boto3.client('cloudwatch')
ssm = boto3.client('secretsmanager')
ses = None

# ---------------------------
# Environment Variables
# ---------------------------
region = os.environ['region']
email_dist_list = os.environ['email_dist_list'].split(",")
source_email = os.environ['source_email_address']
application_error_metric_ns = os.environ['application_error_metric_namespace'].split(",")
env = os.environ["environment"]
is_container_restart_enabled = os.environ["is_container_restart_enabled"]
container_restart_log_stmts = os.environ["log_stmt_for_container_restart"]
container_restart_log_stmts_count = os.environ["log_stmt_for_container_restart_max_count"]
container_restart_approved_alarm_names = os.environ["container_restart_approved_alarm_names"]
high_priority_log_stmts = os.environ["high_priority_log_stmts"]
high_priority_prefix_text = os.environ["high_priority_prefix"]
secret_name = os.environ["secret_name"]

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
    trigger = message['Trigger']

    namespace = None
    metric_name = None

    if 'Metrics' in trigger:   # Composite metrics (array style)
        namespace = trigger['Metrics'][0]['MetricStat']['Metric']['Namespace']
        metric_name = trigger['Metrics'][0]['MetricStat']['Metric']['MetricName']
    elif 'MetricName' in trigger and 'Namespace' in trigger:  # Normal case
        namespace = trigger['Namespace']
        metric_name = trigger['MetricName']

    print(f"Namespace: {namespace}, MetricName: {metric_name}")

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
    print("Log Events: ", response_fle)
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
# Get Log Events (K8s)
# ---------------------------
def get_log_events(log_event_message, log_group_name, pod_name, container_name):
    log_ts_obj = datetime.strptime(log_event_message['ts'], '%Y-%m-%dT%H:%M:%S.%f%z')

    log_stream_name = f"{pod_name}/{container_name}"

    if 'traceId' in log_event_message:
        print(f"The event contains traceId, filtering events based on: {log_event_message['traceId']}")
        filter_pattern = '{$.traceId = "' + log_event_message['traceId'] + '"}'
        log_start_time = log_ts_obj - timedelta(seconds=60)
        log_end_time = log_ts_obj + timedelta(seconds=60)

        response_log_events = cloudwatch_logs.filter_log_events(
            logGroupName=log_group_name,
            startTime=int(log_start_time.timestamp() * 1000),
            endTime=int(log_end_time.timestamp() * 1000),
            filterPattern=filter_pattern
        )
    else:
        print("The event doesn't contain traceId, fetching all log events based on time")
        log_start_time = log_ts_obj - timedelta(seconds=4)
        log_end_time = log_ts_obj + timedelta(seconds=1)

        response_log_events = cloudwatch_logs.get_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            startTime=int(log_start_time.timestamp() * 1000),
            endTime=int(log_end_time.timestamp() * 1000)
        )

    return response_log_events

# ---------------------------
# Consolidate Logs for multiple pods
# ---------------------------
def get_consolidate_log_events(log_group_name, events):
    try:
        first_event = json.loads(events[0]['message'])
        ts_first_event_obj = datetime.strptime(first_event['ts'], '%Y-%m-%dT%H:%M:%S.%f%z')
    except (json.JSONDecodeError, KeyError):
        # fallback: use event timestamp if not JSON
        ts_first_event_obj = datetime.fromtimestamp(events[0]['timestamp'] / 1000.0)

    try:
        last_event = json.loads(events[-1]['message'])
        ts_last_event_obj = datetime.strptime(last_event['ts'], '%Y-%m-%dT%H:%M:%S.%f%z')
    except (json.JSONDecodeError, KeyError):
        ts_last_event_obj = datetime.fromtimestamp(events[-1]['timestamp'] / 1000.0)

    unique_log_streams = list(set([e['logStreamName'] for e in events]))

    params = {
        'logGroupName': log_group_name,
        'logStreamNames': unique_log_streams,
        'startTime': int(ts_first_event_obj.timestamp() * 1000),
        'endTime': int(ts_last_event_obj.timestamp() * 1000)
    }

    consolidated_log_events = []
    counter = 0
    while True:
        response = cloudwatch_logs.filter_log_events(**params)
        counter += 1
        consolidated_log_events.extend(response['events'])

        next_token = response.get('nextToken')
        if not next_token or counter > 10:  # safety guard
            break
        params['nextToken'] = next_token

    return consolidated_log_events

# ---------------------------
# Prepare Email Content for Error Logs (Updated)
# ---------------------------
def prepare_email_content_for_error_logs(response, message, log_group_name):
    raw_events = response.get('events', [])
    if not raw_events:
        print("No events found for error logs.")
        return

    consolidated_events = get_consolidate_log_events(log_group_name, raw_events)

    subject = f"Details for Alarm {message['AlarmName']}"
    alarm_table_html = get_alarm_table(message)
    
    aws_region = os.environ.get('AWS_REGION', 'us-east-1')
    console_url = f'https://{aws_region}.console.aws.amazon.com/cloudwatch/home?region={aws_region}#logsV2:log-groups/log-group/{log_group_name.replace("/", "$252F")}'
    style = "<style> pre {color: red; font-family: arial, sans-serif; font-size: 11px;} </style>"
    
    log_data = f'<br/><b><u>Log Details (Consolidated, showing max 5 events):</u></b><br/><br/>{style}'

    for idx, event in enumerate(consolidated_events[:5]):
        log_stream_name = event['logStreamName']
        raw_message = event['message']
        pod_name, namespace = "N/A", "N/A"

        msg = json.loads(raw_message)
        pod_name = msg.get("containerName")
        namespace = msg.get("containerNamespace")

        print("Pod Name is: " + pod_name + "Namespace is: " + namespace )

        log_data += f'<pre><b>Log Group</b>: <a href="{console_url}/log-events/{log_stream_name}">{log_group_name}</a></pre>'
        log_data += f'<pre><b>Log Stream:</b> {log_stream_name}</pre>'
        log_data += f'<pre><b>K8s Namespace:</b> {namespace}</pre>'
        log_data += f'<pre><b>K8s Pod:</b> {pod_name}</pre>'
        log_data += f'<pre><b>Log Event:</b> {raw_message}</pre><br/>'

        if pod_name != "N/A" and namespace != "N/A":
            print(f"Calling API for pod: {pod_name}, namespace: {namespace}")
            api_call(namespace, pod_name)

    # If more events exist, mention in email
    if len(consolidated_events) > 5:
        log_data += f"<br/><i>Only first 5 events shown. Total events: {len(consolidated_events)}</i><br/>"

    # Send mail with both alarm details and limited log events
    text = alarm_table_html + log_data
    send_email(subject, text)

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
        except json.JSONDecodeError:
            msg = {"logMessage": event['message']}

        if any(s in msg.get('logMessage','') for s in log_stmts):
            container_restart_events.append(msg)
        if any(s in msg.get('logMessage','') for s in high_priority_stmts):
            high_priority = True

    return high_priority, container_restart_events

# ---------------------------
# Restart EKS Deployments
# ---------------------------
def api_call(namespace, pod_name):
    API_TOKEN = get_api_token(secret_name, region)
    url = "https://ucc-dm.est.k8s.dev.dm.aws.spctrm.net/k8s-utils/v1/pods/delete"
    request_data = {
        "name": pod_name,
        "namespace": namespace
    }
    json_data = json.dumps(request_data).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_TOKEN}"
    }

    req = urllib.request.Request(url, data=json_data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as response:
            status_code = response.getcode()
            if status_code == 200:
                print(f"Pod '{pod_name}' deleted successfully in namespace '{namespace}'")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"Pod '{pod_name}' already deleted in namespace '{namespace}'")

# ---------------------------
# Fetch API_TOKEN from Secrets Manager
# ---------------------------
def get_api_token(secret_name, region):
    secrets_client = boto3.client('secretsmanager', region_name=region)
    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret = json.loads(response['SecretString'])
        return secret['API_TOKEN']
    except Exception as e:
        print(f"Error retrieving secret: {e}")
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
def send_email(subject, text):
    global ses
    global email_dist_list

    if ses is None:
        ses = boto3.client('ses', region_name=region)
    try:
        response_ses = ses.send_email(
            Source=source_email,
            Destination={
                'BccAddresses': email_dist_list
            },
            Message={
                'Subject': {
                    'Data': subject
                },
                'Body': {
                    'Html': {
                        'Data': text
                    }
                }
            }
        )

        print("Response from SES: {}".format(json.dumps(response_ses)))
    except Exception as e:
        print("[#ERROR#]: Error occurred while Sending Email: {}".format(str(e)))
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
