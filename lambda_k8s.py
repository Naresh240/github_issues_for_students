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
# Upload to S3 and return link
# ---------------------------
def get_s3_download_link(response_log_events):
    
    length_events = len(response_log_events)
    with open("/tmp/logs.txt", "w+") as a_file:
        for log_event in range(length_events):
            a_file.write(
                "%s\n" % response_log_events[log_event]['message'])

    with open("/tmp/logs.txt", 'rb') as orig_file:
        with gzip.open("/tmp/logs.gz", 'wb') as zipped_file:
            zipped_file.writelines(orig_file)

    file_name = str(uuid.uuid4()) + '.gz'
    log_file_name = "prod/" + file_name
    result = s3_client.upload_file(
        '/tmp/logs.gz', 'ucchub2-app-logs', log_file_name)
    print("Log file uploaded successfully to S3: {}".format(log_file_name))

    return "https://lo1v82nhf5.execute-api.us-east-1.amazonaws.com/cw/v1/download/" + file_name

# ---------------------------
# Prepare Email Content for Error Logs (Updated)
# ---------------------------
def prepare_email_content_for_error_logs(response, message, log_group_name):
    high_priority_notification = False
    events = response['events']
    subject = f"Details for Alarm - {message['AlarmName']}"
    alarm_table_html = get_alarm_table(message)

    console_url = f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{log_group_name.replace('/', '$252F')}"

    style = "<style> pre {color: black;font-family: monospace;font-size: 12px;white-space: pre-wrap;} </style>"
    log_data = '<br/><b><u>Log Details:</u></b><br/>' + style

    # Limit logs shown directly in email
    max_logs_in_email = 20
    logs_to_show = events[:max_logs_in_email]

    cleaned_logs = []
    for event in logs_to_show:
        try:
            msg = json.loads(event['message'])
            if isinstance(msg, dict):
                # Keep only useful parts
                filtered = {
                    "timestamp": msg.get("ts", event.get("timestamp")),
                    "level": msg.get("logLevel"),
                    "message": msg.get("logMessage", msg)
                }
                cleaned_logs.append(filtered)
            else:
                cleaned_logs.append({"message": msg})
        except Exception:
            cleaned_logs.append({"message": event['message']})

    pretty_logs = json.dumps(cleaned_logs, indent=4, ensure_ascii=False)
    log_data += f"<pre>{html.escape(pretty_logs)}</pre>"

    # If too many logs, upload all to S3 and include a link
    if len(events) > max_logs_in_email:
        consolidated_logs = get_consolidate_log_events(log_group_name, events)
        download_link = get_s3_download_link(consolidated_logs)
        log_data += f'<br/><b>More logs available:</b> <a href="{download_link}">Download Full Log File</a>'

    restarted_log_data = ""
    if is_container_restart_enabled.lower() == "true" and message['AlarmName'] in approved_alarms_list:
        high_priority_notification, container_restart_log_events = check_events_for_los_stmts(events)
        if len(container_restart_log_events) >= int(container_restart_log_stmts_count):
            restarted_container_ids = restart_containers_eks(container_restart_log_events)
            if restarted_container_ids:
                restarted_log_data += "<br/><b>Restarted Containers:</b><ol>"
                for container_id in restarted_container_ids:
                    restarted_log_data += f"<li>{container_id}</li>"
                restarted_log_data += "</ol>"

    # Final email body
    text = alarm_table_html + restarted_log_data + log_data
    text += f"<br><br><u><b>Source Identifier:</b></u> {log_stream}"

    if high_priority_notification:
        subject = f"{high_priority_prefix_text}: {subject}"

    send_email(subject, text)
    print("Email Sent.")

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
