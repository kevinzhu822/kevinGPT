import boto3
import json
import time
import re
import os
from datetime import datetime, timezone
from urllib.request import urlopen, Request

ec2 = boto3.client('ec2', region_name='us-east-1')
ssm = boto3.client('ssm', region_name='us-east-1')
ce = boto3.client('ce')
secretsmanager = boto3.client('secretsmanager', region_name='us-east-1')  # secrets manager client

allowed_origins = [
    "http://admin.kevin-zhu.com.s3-website-us-east-1.amazonaws.com",
    "https://d2j6rfgh7rul9g.cloudfront.net",
    "https://admin.kevin-zhu.com"
]
cors_headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, authorization, Content-Type, X-Requested-With",
    "Access-Control-Allow-Credentials": "true",
}
INSTANCE_ID = 'i-0a7cadc0f412cdcc6'

protected_ops = ['start', 'stop', 'logs', 'aws-cost', 'openai-cost']


def lambda_handler(event, context):
    print('HELLO!!!--')
    print(event)
    print(context)
    method = event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method", "")
    if method == "OPTIONS":
        origin = event['headers'].get('origin', 'kevin')
        if origin in allowed_origins or True:
            cors_headers["Access-Control-Allow-Origin"] = origin

        return {
            'statusCode': 204,
            'headers': cors_headers,
            'body': ''
        }

    op = event.get('queryStringParameters', {}).get('op', 'status')

    try:
        if op in protected_ops:
            token = event['headers'].get('authorization', '').split(' ')[1]
            if not token:
                return respond(401, {'message': 'Unauthorized'})
        if op == 'health':
            health_check_url = 'https://chat.kevin-zhu.com/health'
            try:
                with urlopen(health_check_url) as response:
                    if response.status == 200:
                        return respond(200, {'message': 'Health check passed'})
                    else:
                        return respond(500, {'message': 'Health check failed'})
            except Exception as e:
                return respond(500, {'error': str(e)})

        elif op == 'start':
            state = get_instance_state(INSTANCE_ID)
            if state == 'running':
                return respond(409, {"message": "Invalid Request: Instance is already running"})

            ec2.start_instances(InstanceIds=[INSTANCE_ID])
            return respond(200, {'message': 'Instance starting up'})

        elif op == 'stop':
            state = get_instance_state(INSTANCE_ID)
            if state == 'stopped':
                return respond(409, {"message": "Invalid Request: Instance is already stopped"})

            ec2.stop_instances(InstanceIds=[INSTANCE_ID])
            return respond(200, {'message': 'Stop request sent'})

        elif op == 'status':
            instance_info = ec2.describe_instances(InstanceIds=[INSTANCE_ID])
            instance = instance_info['Reservations'][0]['Instances'][0]
            state = instance['State']['Name']
            transition_reason_raw = instance.get('StateTransitionReason', '')

            match = re.search(r'\((.*?) GMT\)', transition_reason_raw)
            if match:
                last_changed_dt = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                last_changed = last_changed_dt.isoformat()
            else:
                last_changed = None

            if "User initiated" in transition_reason_raw:
                last_changed_reason = "user"
            elif "Client" in transition_reason_raw:
                last_changed_reason = "client"
            elif "Server" in transition_reason_raw:
                last_changed_reason = "server"
            elif transition_reason_raw == "":
                last_changed_reason = "none"
            else:
                last_changed_reason = "unknown"

            status_resp = ec2.describe_instance_status(
                InstanceIds=[INSTANCE_ID],
                IncludeAllInstances=True
            )

            if status_resp['InstanceStatuses']:
                system_status = status_resp['InstanceStatuses'][0]['SystemStatus']['Status']
                instance_status = status_resp['InstanceStatuses'][0]['InstanceStatus']['Status']
            else:
                system_status = instance_status = 'unknown'

            return respond(200, {
                'state': state,
                'lastChangedTime': last_changed,
                'lastChangedReason': last_changed_reason,
                'systemStatus': system_status,
                'instanceStatus': instance_status
            })

        elif op == 'logs':
            state = get_instance_state(INSTANCE_ID)
            if state != 'running':
                return respond(409, {"message": "Invalid Request: Instance is not running"})

            command = "docker ps -qf 'name=openwebui' | xargs -r docker logs --tail 50"
            ssm_resp = ssm.send_command(
                InstanceIds=[INSTANCE_ID],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [command]},
            )
            command_id = ssm_resp['Command']['CommandId']

            time.sleep(2)

            output = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=INSTANCE_ID,
            )

            return respond(200, {
                'output': output['StandardOutputContent'] or output['StandardErrorContent']
            })

        elif op == 'aws-cost':
            today = datetime.today()
            start = today.replace(day=1).strftime('%Y-%m-%d')
            end = today.strftime('%Y-%m-%d')

            response = ce.get_cost_and_usage(
                TimePeriod={
                    'Start': start,
                    'End': end
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    }
                ]
            )

            services = []
            for group in response['ResultsByTime'][0]['Groups']:
                service_name = group['Keys'][0]
                amount = group['Metrics']['UnblendedCost']['Amount']
                services.append({
                    'service': service_name,
                    'cost': amount
                })

            return respond(200, {
                'start': start,
                'end': end,
                'services': services
            })

        elif op == 'openai-cost':
            # Get OpenAI API key from Secrets Manager
            secret_resp = secretsmanager.get_secret_value(SecretId='kevingpt-secrets')
            secrets = json.loads(secret_resp['SecretString'])
            openai_admin_key = secrets['OPENAI_ADMIN_KEY']

            now = datetime.now(timezone.utc)
            start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            start_unix = int(start_of_month.timestamp())
            end_unix = int(now.timestamp())

            total = 0.0
            currency = 'usd'
            next_page = None
            line_items = {}  # Store cost per model/line_item

            while True:
                # Build URL (always group_by=line_item)
                url = f"https://api.openai.com/v1/organization/costs?start_time={start_unix}&end_time={end_unix}&group_by=line_item"
                if next_page:
                    url += f"&page={next_page}"

                req = Request(url, headers={
                    'Authorization': f'Bearer {openai_admin_key}',
                    'Content-Type': 'application/json'
                })

                with urlopen(req) as resp:
                    resp_data = json.loads(resp.read().decode())

                # Add up costs
                for bucket in resp_data.get('data', []):
                    for result in bucket.get('results', []):
                        amount = result.get('amount', {}).get('value', 0.0)
                        currency = result.get('amount', {}).get('currency', 'usd')
                        model_name = result.get('line_item', 'unknown')

                        total += amount

                        if model_name not in line_items:
                            line_items[model_name] = 0.0
                        line_items[model_name] += amount

                # Check if more pages
                if resp_data.get('has_more'):
                    next_page = resp_data.get('next_page')
                else:
                    break

            return respond(200, {
                'start_time': start_unix,
                'end_time': end_unix,
                'totalOpenAICost': round(total, 4),
                'currency': currency,
                'lineItems': {k: round(v, 4) for k, v in line_items.items()}
            })



        else:
            return respond(400, {'error': f'Unknown operation: {op}'})

    except Exception as e:
        return respond(500, {'error': str(e)})


def respond(status_code, body):
    print("body:")
    print(body)
    print('--GOODBYE!!!!')
    return {
        'statusCode': status_code,
        'headers': {
            **cors_headers,
            'Content-Type': 'application/json'
        },
        'body': json.dumps(body)
    }

def get_instance_state(instance_id):
    response = ec2.describe_instances(InstanceIds=[instance_id])
    state = response['Reservations'][0]['Instances'][0]['State']['Name']
    return state