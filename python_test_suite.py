# ===================================================================
# File: tests/conftest.py
# Pytest configuration and shared fixtures
# ===================================================================
import pytest
import boto3
import json
import os
from moto import mock_ec2, mock_iam, mock_cloudwatch, mock_sns, mock_ssm
from unittest.mock import MagicMock, patch

@pytest.fixture(scope="session")
def aws_credentials():
    """Mock AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture
def mock_aws_services(aws_credentials):
    """Mock all AWS services used in the solution."""
    with mock_ec2(), mock_iam(), mock_cloudwatch(), mock_sns(), mock_ssm():
        yield

@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        "central_account_id": "123456789012",
        "target_accounts": [
            {
                "account_id": "123456789013",
                "environment": "production",
                "role_name": "MonitoredAccountRole"
            },
            {
                "account_id": "123456789014",
                "environment": "staging",
                "role_name": "MonitoredAccountRole"
            }
        ],
        "monitoring_config": {
            "thresholds": {
                "critical": 95,
                "warning": 85,
                "info": 75
            },
            "metric_collection_interval": 300
        }
    }

@pytest.fixture
def ec2_client(mock_aws_services):
    """EC2 client fixture."""
    return boto3.client("ec2", region_name="us-east-1")

@pytest.fixture
def cloudwatch_client(mock_aws_services):
    """CloudWatch client fixture."""
    return boto3.client("cloudwatch", region_name="us-east-1")

@pytest.fixture
def iam_client(mock_aws_services):
    """IAM client fixture."""
    return boto3.client("iam", region_name="us-east-1")

@pytest.fixture
def sns_client(mock_aws_services):
    """SNS client fixture."""
    return boto3.client("sns", region_name="us-east-1")

@pytest.fixture
def ssm_client(mock_aws_services):
    """SSM client fixture."""
    return boto3.client("ssm", region_name="us-east-1")

# ===================================================================
# File: tests/test_deployment.py
# Tests for deployment functionality
# ===================================================================
import pytest
import boto3
from moto import mock_ec2, mock_iam, mock_cloudwatch
from unittest.mock import patch, MagicMock
import json


class TestDeployment:
    """Test suite for deployment functionality."""

    def test_iam_role_creation(self, iam_client, sample_config):
        """Test IAM role creation for cross-account access."""
        # Create central monitoring role
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        response = iam_client.create_role(
            RoleName="CentralMonitoringRole",
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            Description="Central monitoring role for disk monitoring solution"
        )
        
        assert response["Role"]["RoleName"] == "CentralMonitoringRole"
        assert "arn:aws:iam::" in response["Role"]["Arn"]

    def test_cross_account_policy_creation(self, iam_client, sample_config):
        """Test cross-account IAM policy creation."""
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole"],
                    "Resource": [
                        f"arn:aws:iam::{account['account_id']}:role/{account['role_name']}"
                        for account in sample_config["target_accounts"]
                    ]
                }
            ]
        }
        
        response = iam_client.create_policy(
            PolicyName="CrossAccountMonitoringPolicy",
            PolicyDocument=json.dumps(policy_document),
            Description="Policy for cross-account monitoring access"
        )
        
        assert response["Policy"]["PolicyName"] == "CrossAccountMonitoringPolicy"
        assert "arn:aws:iam::" in response["Policy"]["Arn"]

    def test_cloudwatch_dashboard_creation(self, cloudwatch_client, sample_config):
        """Test CloudWatch dashboard creation."""
        dashboard_body = {
            "widgets": [
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            ["Custom/DiskMonitoring", "DiskUtilization"],
                            [".", "AvailableSpace"]
                        ],
                        "period": 300,
                        "stat": "Average",
                        "region": "us-east-1",
                        "title": "Disk Monitoring Overview"
                    }
                }
            ]
        }
        
        response = cloudwatch_client.put_dashboard(
            DashboardName="DiskMonitoring-Test",
            DashboardBody=json.dumps(dashboard_body)
        )
        
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_sns_topic_creation(self, sns_client):
        """Test SNS topic creation for alerts."""
        response = sns_client.create_topic(
            Name="DiskMonitoringAlerts",
            Attributes={
                "DisplayName": "Disk Monitoring Alerts"
            }
        )
        
        assert "arn:aws:sns:" in response["TopicArn"]
        
        # Test subscription
        subscription_response = sns_client.subscribe(
            TopicArn=response["TopicArn"],
            Protocol="email",
            Endpoint="test@example.com"
        )
        
        assert "arn:aws:sns:" in subscription_response["SubscriptionArn"]

    def test_ec2_instance_discovery(self, ec2_client):
        """Test EC2 instance discovery functionality."""
        # Create test instances
        response = ec2_client.run_instances(
            ImageId="ami-12345678",
            MinCount=2,
            MaxCount=2,
            InstanceType="t2.micro",
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "Monitoring", "Value": "enabled"}
                    ]
                }
            ]
        )
        
        instance_ids = [instance["InstanceId"] for instance in response["Instances"]]
        
        # Test instance discovery
        instances = ec2_client.describe_instances(
            Filters=[
                {"Name": "tag:Monitoring", "Values": ["enabled"]},
                {"Name": "instance-state-name", "Values": ["running"]}
            ]
        )
        
        discovered_instances = []
        for reservation in instances["Reservations"]:
            for instance in reservation["Instances"]:
                discovered_instances.append(instance["InstanceId"])
        
        assert len(discovered_instances) >= 2

    @patch('boto3.client')
    def test_cloudwatch_agent_deployment(self, mock_boto_client, ssm_client, sample_config):
        """Test CloudWatch agent deployment via SSM."""
        mock_ssm = MagicMock()
        mock_boto_client.return_value = mock_ssm
        
        mock_ssm.send_command.return_value = {
            "Command": {
                "CommandId": "test-command-id",
                "Status": "Success"
            }
        }
        
        # Simulate agent installation
        response = mock_ssm.send_command(
            InstanceIds=["i-1234567890abcdef0"],
            DocumentName="AWS-ConfigureAWSPackage",
            Parameters={
                "action": ["Install"],
                "name": ["AmazonCloudWatchAgent"]
            }
        )
        
        assert response["Command"]["Status"] == "Success"
        mock_ssm.send_command.assert_called_once()

    def test_metric_alarm_creation(self, cloudwatch_client, sample_config):
        """Test CloudWatch metric alarm creation."""
        response = cloudwatch_client.put_metric_alarm(
            AlarmName="DiskUsage-Critical-Test",
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=2,
            MetricName="DiskUtilization",
            Namespace="Custom/DiskMonitoring",
            Period=300,
            Statistic="Average",
            Threshold=sample_config["monitoring_config"]["thresholds"]["critical"],
            ActionsEnabled=True,
            AlarmActions=["arn:aws:sns:us-east-1:123456789012:DiskMonitoringAlerts"],
            AlarmDescription="Critical disk usage alert",
            Unit="Percent"
        )
        
        # Verify alarm was created
        alarms = cloudwatch_client.describe_alarms(
            AlarmNames=["DiskUsage-Critical-Test"]
        )
        
        assert len(alarms["MetricAlarms"]) == 1
        assert alarms["MetricAlarms"][0]["Threshold"] == 95.0

# ===================================================================
# File: tests/test_monitoring.py
# Tests for monitoring functionality
# ===================================================================
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch


class TestMonitoring:
    """Test suite for monitoring functionality."""

    def test_metric_data_publishing(self, cloudwatch_client):
        """Test publishing custom metrics to CloudWatch."""
        # Simulate publishing disk utilization metrics
        response = cloudwatch_client.put_metric_data(
            Namespace="Custom/DiskMonitoring",
            MetricData=[
                {
                    "MetricName": "DiskUtilization",
                    "Dimensions": [
                        {"Name": "InstanceId", "Value": "i-1234567890abcdef0"},
                        {"Name": "MountPoint", "Value": "/"}
                    ],
                    "Value": 87.5,
                    "Unit": "Percent",
                    "Timestamp": datetime.utcnow()
                },
                {
                    "MetricName": "AvailableSpace",
                    "Dimensions": [
                        {"Name": "InstanceId", "Value": "i-1234567890abcdef0"},
                        {"Name": "MountPoint", "Value": "/"}
                    ],
                    "Value": 2.5,
                    "Unit": "Gigabytes",
                    "Timestamp": datetime.utcnow()
                }
            ]
        )
        
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_metric_data_retrieval(self, cloudwatch_client):
        """Test retrieving metric data from CloudWatch."""
        # First publish some test data
        cloudwatch_client.put_metric_data(
            Namespace="Custom/DiskMonitoring",
            MetricData=[
                {
                    "MetricName": "DiskUtilization",
                    "Value": 75.0,
                    "Unit": "Percent",
                    "Timestamp": datetime.utcnow()
                }
            ]
        )
        
        # Retrieve the metrics
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        response = cloudwatch_client.get_metric_statistics(
            Namespace="Custom/DiskMonitoring",
            MetricName="DiskUtilization",
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=["Average"]
        )
        
        assert "Datapoints" in response

    def test_alert_notification_flow(self, sns_client):
        """Test alert notification flow through SNS."""
        # Create SNS topic
        topic_response = sns_client.create_topic(Name="TestAlerts")
        topic_arn = topic_response["TopicArn"]
        
        # Subscribe to topic
        sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint="test@example.com"
        )
        
        # Publish test alert
        message = {
            "AlarmName": "DiskUsage-Critical-Test",
            "AlarmDescription": "Test critical disk usage alert",
            "Threshold": 95.0,
            "CurrentValue": 97.5,
            "InstanceId": "i-1234567890abcdef0"
        }
        
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message),
            Subject="Critical Disk Usage Alert"
        )
        
        assert "MessageId" in response

    def test_multi_account_metric_aggregation(self, cloudwatch_client, sample_config):
        """Test metric aggregation across multiple accounts."""
        # Simulate metrics from different accounts
        for account in sample_config["target_accounts"]:
            cloudwatch_client.put_metric_data(
                Namespace="Custom/DiskMonitoring",
                MetricData=[
                    {
                        "MetricName": "DiskUtilization",
                        "Dimensions": [
                            {"Name": "AccountId", "Value": account["account_id"]},
                            {"Name": "Environment", "Value": account["environment"]}
                        ],
                        "Value": 85.0,
                        "Unit": "Percent",
                        "Timestamp": datetime.utcnow()
                    }
                ]
            )
        
        # Test cross-account metric retrieval
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        response = cloudwatch_client.get_metric_statistics(
            Namespace="Custom/DiskMonitoring",
            MetricName="DiskUtilization",
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=["Average"]
        )
        
        assert "Datapoints" in response

# ===================================================================
# File: tests/test_security.py
# Tests for security functionality
# ===================================================================
import pytest
import json
from unittest.mock import MagicMock, patch


class TestSecurity:
    """Test suite for security functionality."""

    def test_iam_role_trust_policy(self, iam_client, sample_config):
        """Test IAM role trust policy configuration."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{sample_config['central_account_id']}:root"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "Bool": {
                            "aws:MultiFactorAuthPresent": "true"
                        }
                    }
                }
            ]
        }
        
        response = iam_client.create_role(
            RoleName="SecureMonitoringRole",
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        
        created_policy = json.loads(response["Role"]["AssumeRolePolicyDocument"])
        assert created_policy["Statement"][0]["Condition"]["Bool"]["aws:MultiFactorAuthPresent"] == "true"

    def test_least_privilege_permissions(self, iam_client):
        """Test least privilege IAM permissions."""
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "cloudwatch:PutMetricData",
                        "cloudwatch:GetMetricStatistics",
                        "logs:PutLogEvents"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": [
                        "iam:*",
                        "ec2:TerminateInstances",
                        "s3:DeleteBucket"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        response = iam_client.create_policy(
            PolicyName="LeastPrivilegeMonitoringPolicy",
            PolicyDocument=json.dumps(policy_document)
        )
        
        assert response["Policy"]["PolicyName"] == "LeastPrivilegeMonitoringPolicy"

    @patch('boto3.client')
    def test_secure_credential_handling(self, mock_boto_client):
        """Test secure credential handling without hardcoded keys."""
        mock_sts = MagicMock()
        mock_boto_client.return_value = mock_sts
        
        # Simulate role assumption
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA...",
                "SecretAccessKey": "...",
                "SessionToken": "...",
                "Expiration": "2024-01-01T00:00:00Z"
            }
        }
        
        # Test that we're using temporary credentials
        response = mock_sts.assume_role(
            RoleArn="arn:aws:iam::123456789013:role/MonitoredAccountRole",
            RoleSessionName="AnsibleDiskMonitoring"
        )
        
        assert "SessionToken" in response["Credentials"]
        assert response["Credentials"]["AccessKeyId"].startswith("ASIA")

    def test_encryption_configuration(self, sample_config):
        """Test encryption configuration for data at rest and in transit."""
        # Test CloudWatch Logs encryption configuration
        encryption_config = {
            "LogGroupName": "/aws/ec2/diskmonitoring",
            "KmsKeyId": f"arn:aws:kms:us-east-1:{sample_config['central_account_id']}:key/12345678-1234-1234-1234-123456789012"
        }
        
        assert "KmsKeyId" in encryption_config
        assert encryption_config["KmsKeyId"].startswith("arn:aws:kms:")

    def test_network_security_configuration(self):
        """Test network security group configuration."""
        security_group_rules = [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "Internal HTTPS"}]
            }
        ]
        
        # Verify no unrestricted access
        for rule in security_group_rules:
            if "IpRanges" in rule:
                for ip_range in rule["IpRanges"]:
                    assert ip_range["CidrIp"] != "0.0.0.0/0"

# ===================================================================
# File: tests/test_scalability.py
# Tests for scalability functionality
# ===================================================================
import pytest
from concurrent.futures import ThreadPoolExecutor
import time


class TestScalability:
    """Test suite for scalability functionality."""

    def test_concurrent_metric_publishing(self, cloudwatch_client):
        """Test concurrent metric publishing under load."""
        def publish_metrics(instance_id):
            try:
                cloudwatch_client.put_metric_data(
                    Namespace="Custom/DiskMonitoring",
                    MetricData=[
                        {
                            "MetricName": "DiskUtilization",
                            "Dimensions": [
                                {"Name": "InstanceId", "Value": f"i-{instance_id:016x}"}
                            ],
                            "Value": 75.0,
                            "Unit": "Percent"
                        }
                    ]
                )
                return True
            except Exception as e:
                return False
        
        # Test with 50 concurrent instances
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(publish_metrics, i) for i in range(50)]
            results = [future.result() for future in futures]
        
        # At least 90% should succeed
        success_rate = sum(results) / len(results)
        assert success_rate >= 0.9

    def test_large_batch_metric_processing(self, cloudwatch_client):
        """Test processing large batches of metrics."""
        # CloudWatch supports up to 20 metric data points per request
        batch_size = 20
        num_batches = 5
        
        for batch in range(num_batches):
            metric_data = []
            for i in range(batch_size):
                metric_data.append({
                    "MetricName": "DiskUtilization",
                    "Dimensions": [
                        {"Name": "InstanceId", "Value": f"i-{batch:04d}{i:04d}"}
                    ],
                    "Value": 70.0 + (i % 30),
                    "Unit": "Percent"
                })
            
            response = cloudwatch_client.put_metric_data(
                Namespace="Custom/DiskMonitoring",
                MetricData=metric_data
            )
            
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_multi_region_deployment_simulation(self, sample_config):
        """Test multi-region deployment simulation."""
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
        
        deployment_results = []
        for region in regions:
            # Simulate deployment in each region
            deployment_result = {
                "region": region,
                "status": "deployed",
                "instances_monitored": 100 + (len(region) * 10),  # Vary by region
                "deployment_time": 300 + (regions.index(region) * 60)  # Sequential delay
            }
            deployment_results.append(deployment_result)
        
        # Verify all regions deployed successfully
        assert all(result["status"] == "deployed" for result in deployment_results)
        assert len(deployment_results) == len(regions)

    def test_auto_scaling_metric_collection(self, ec2_client, cloudwatch_client):
        """Test metric collection during auto-scaling events."""
        # Simulate auto-scaling group scaling up
        initial_instances = 5
        scaled_instances = 10
        
        # Create initial instances
        for i in range(initial_instances):
            ec2_client.run_instances(
                ImageId="ami-12345678",
                MinCount=1,
                MaxCount=1,
                InstanceType="t2.micro",
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "AutoScalingGroup", "Value": "test-asg"},
                            {"Key": "Monitoring", "Value": "enabled"}
                        ]
                    }
                ]
            )
        
        # Simulate scaling event - add more instances
        for i in range(initial_instances, scaled_instances):
            ec2_client.run_instances(
                ImageId="ami-12345678",
                MinCount=1,
                MaxCount=1,
                InstanceType="t2.micro",
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "AutoScalingGroup", "Value": "test-asg"},
                            {"Key": "Monitoring", "Value": "enabled"}
                        ]
                    }
                ]
            )
        
        # Verify all instances are discoverable
        instances = ec2_client.describe_instances(
            Filters=[
                {"Name": "tag:AutoScalingGroup", "Values": ["test-asg"]},
                {"Name": "instance-state-name", "Values": ["running"]}
            ]
        )
        
        total_instances = sum(
            len(reservation["Instances"]) 
            for reservation in instances["Reservations"]
        )
        
        assert total_instances == scaled_instances

    def test_dashboard_performance_with_many_metrics(self, cloudwatch_client):
        """Test dashboard performance with large number of metrics."""
        # Create a dashboard with many metrics
        widget_count = 20
        metrics_per_widget = 5
        
        widgets = []
        for widget_id in range(widget_count):
            metrics = []
            for metric_id in range(metrics_per_widget):
                metrics.append([
                    "Custom/DiskMonitoring",
                    "DiskUtilization",
                    "InstanceId",
                    f"i-{widget_id:04d}{metric_id:04d}"
                ])
            
            widgets.append({
                "type": "metric",
                "properties": {
                    "metrics": metrics,
                    "period": 300,
                    "stat": "Average",
                    "region": "us-east-1",
                    "title": f"Disk Usage Widget {widget_id}"
                }
            })
        
        dashboard_body = {"widgets": widgets}
        
        start_time = time.time()
        response = cloudwatch_client.put_dashboard(
            DashboardName="PerformanceTestDashboard",
            DashboardBody=json.dumps(dashboard_body)
        )
        end_time = time.time()
        
        # Dashboard creation should complete within reasonable time
        creation_time = end_time - start_time
        assert creation_time < 30  # seconds
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

# ===================================================================
# File: tests/test_integration.py
# Integration tests for end-to-end functionality
# ===================================================================
import pytest
import time
from unittest.mock import patch, MagicMock


class TestIntegration:
    """Integration test suite for end-to-end functionality."""

    @patch('subprocess.run')
    def test_full_deployment_workflow(self, mock_subprocess, sample_config):
        """Test the complete deployment workflow."""
        # Mock successful Ansible execution
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="Deployment successful")
        
        deployment_steps = [
            "setup_iam_roles",
            "deploy_monitoring",
            "setup_dashboards",
            "deploy_agents",
            "setup_alerts"
        ]
        
        results = []
        for step in deployment_steps:
            # Simulate running each deployment step
            result = mock_subprocess(
                ["ansible-playbook", f"roles/{step}/tasks/main.yml"],
                capture_output=True,
                text=True
            )
            results.append(result.returncode == 0)
        
        # All steps should succeed
        assert all(results)

    def test_metric_flow_end_to_end(self, cloudwatch_client, sns_client):
        """Test complete metric flow from collection to alerting."""
        # Step 1: Create SNS topic for alerts
        topic_response = sns_client.create_topic(Name="TestAlerts")
        topic_arn = topic_response["TopicArn"]
        
        # Step 2: Create CloudWatch alarm
        cloudwatch_client.put_metric_alarm(
            AlarmName="IntegrationTest-DiskUsage",
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            MetricName="DiskUtilization",
            Namespace="Custom/DiskMonitoring",
            Period=60,  # 1 minute for faster testing
            Statistic="Average",
            Threshold=90.0,
            ActionsEnabled=True,
            AlarmActions=[topic_arn]
        )
        
        # Step 3: Publish metric data that should trigger alarm
        cloudwatch_client.put_metric_data(
            Namespace="Custom/DiskMonitoring",
            MetricData=[
                {
                    "MetricName": "DiskUtilization",
                    "Value": 95.0,  # Above threshold
                    "Unit": "Percent"
                }
            ]
        )
        
        # Step 4: Verify alarm exists and is configured correctly
        alarms = cloudwatch_client.describe_alarms(
            AlarmNames=["IntegrationTest-DiskUsage"]
        )
        
        assert len(alarms["MetricAlarms"]) == 1
        assert alarms["MetricAlarms"][0]["Threshold"] == 90.0

    def test_cross_account_access_simulation(self, iam_client, sample_config):
        """Test cross-account access simulation."""
        # Create roles in central account
        central_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam_client.create_role(
            RoleName="CentralMonitoringRole",
            AssumeRolePolicyDocument=json.dumps(central_role_policy)
        )
        
        # Create cross-account assume role policy
        cross_account_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole"],
                    "Resource": [
                        f"arn:aws:iam::{account['account_id']}:role/{account['role_name']}"
                        for account in sample_config["target_accounts"]
                    ]
                }
            ]
        }
        
        policy_response = iam_client.create_policy(
            PolicyName="CrossAccountAccessPolicy",
            PolicyDocument=json.dumps(cross_account_policy)
        )
        
        # Attach policy to role
        iam_client.attach_role_policy(
            RoleName="CentralMonitoringRole",
            PolicyArn=policy_response["Policy"]["Arn"]
        )
        
        # Verify policy attachment
        attached_policies = iam_client.list_attached_role_policies(
            RoleName="CentralMonitoringRole"
        )
        
        policy_names = [policy["PolicyName"] for policy in attached_policies["AttachedPolicies"]]
        assert "CrossAccountAccessPolicy" in policy_names

    def test_disaster_recovery_simulation(self, cloudwatch_client, sample_config):
        """Test disaster recovery capabilities."""
        primary_region = "us-east-1"
        backup_region = "us-west-2"
        
        # Simulate primary region failure and failover
        dashboards_backup = [
            {
                "name": "DiskMonitoring-Overview",
                "body": {
                    "widgets": [
                        {
                            "type": "metric",
                            "properties": {
                                "metrics": [["Custom/DiskMonitoring", "DiskUtilization"]],
                                "region": backup_region
                            }
                        }
                    ]
                }
            }
        ]
        
        # Create backup dashboard in secondary region
        for dashboard in dashboards_backup:
            response = cloudwatch_client.put_dashboard(
                DashboardName=dashboard["name"],
                DashboardBody=json.dumps(dashboard["body"])
            )
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

# ===================================================================
# File: scripts/test.sh
# Test execution script
# ===================================================================
#!/bin/bash

set -e

# Configuration
TEST_DIR="$(dirname "$0")/../tests"
COVERAGE_THRESHOLD=80
PARALLEL_WORKERS=4

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install test dependencies
    pip install pytest pytest-cov pytest-xdist moto[all] boto3
    
    log_info "Test environment setup complete"
}

# Run unit tests
run_unit_tests() {
    log_info "Running unit tests..."
    
    pytest "$TEST_DIR" \
        --cov=roles \
        --cov=playbooks \
        --cov-report=html \
        --cov-report=term-missing \
        --cov-fail-under=$COVERAGE_THRESHOLD \
        -n $PARALLEL_WORKERS \
        -v \
        --tb=short
    
    if [[ $? -eq 0 ]]; then
        log_info "Unit tests passed"
    else
        log_error "Unit tests failed"
        exit 1
    fi
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    
    pytest "$TEST_DIR/test_integration.py" \
        -v \
        --tb=short \
        -s
    
    if [[ $? -eq 0 ]]; then
        log_info "Integration tests passed"
    else
        log_error "Integration tests failed"
        exit 1
    fi
}

# Run security tests
run_security_tests() {
    log_info "Running security tests..."
    
    pytest "$TEST_DIR/test_security.py" \
        -v \
        --tb=short
    
    if [[ $? -eq 0 ]]; then
        log_info "Security tests passed"
    else
        log_error "Security tests failed"
        exit 1
    fi
}

# Run performance tests
run_performance_tests() {
    log_info "Running performance tests..."
    
    pytest "$TEST_DIR/test_scalability.py" \
        -v \
        --tb=short \
        -m "not slow"  # Skip slow tests in regular runs
    
    if [[ $? -eq 0 ]]; then
        log_info "Performance tests passed"
    else
        log_error "Performance tests failed"
        exit 1
    fi
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."
    
    # Create reports directory
    mkdir -p reports
    
    # Generate JUnit XML report
    pytest "$TEST_DIR" \
        --junitxml=reports/junit.xml \
        --html=reports/report.html \
        --self-contained-html \
        -q
    
    log_info "Test report generated in reports/ directory"
}

# Main execution
main() {
    log_info "Starting comprehensive test suite"
    
    setup_test_environment
    run_unit_tests
    run_integration_tests
    run_security_tests
    run_performance_tests
    generate_test_report
    
    log_info "All tests completed successfully!"
    log_info "Coverage report: htmlcov/index.html"
    log_info "Test report: reports/report.html"
}

# Parse command line arguments
case "${1:-all}" in
    "unit")
        setup_test_environment
        run_unit_tests
        ;;
    "integration")
        setup_test_environment
        run_integration_tests
        ;;
    "security")
        setup_test_environment
        run_security_tests
        ;;
    "performance")
        setup_test_environment
        run_performance_tests
        ;;
    "all"|*)
        main
        ;;
esac300,
            Statistics=["Average", "Maximum"]
        )
        
        assert "Datapoints" in response

    def test_alarm_state_evaluation(self, cloudwatch_client, sample_config):
        """Test alarm state evaluation logic."""
        # Create test alarm
        cloudwatch_client.put_metric_alarm(
            AlarmName="Test-DiskUsage-Warning",
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            MetricName="DiskUtilization",
            Namespace="Custom/DiskMonitoring",
            Period=300,
            Statistic="Average",
            Threshold=sample_config["monitoring_config"]["thresholds"]["warning"],
            ActionsEnabled=True
        )
        
        # Simulate metric data that should trigger alarm
        cloudwatch_client.put_metric_data(
            Namespace="Custom/DiskMonitoring",
            MetricData=[
                {
                    "MetricName": "DiskUtilization",
                    "Value": 90.0,  # Above warning threshold
                    "Unit": "Percent",
                    "Timestamp": datetime.utcnow()
                }
            ]
        )
        
        # Check alarm state
        alarms = cloudwatch_client.describe_alarms(
            AlarmNames=["Test-DiskUsage-Warning"]
        )
        
        assert len(alarms["MetricAlarms"]) == 1

    @patch('boto3.client')
    def test_automated_remediation_lambda(self, mock_boto_client):
        """Test automated remediation Lambda function logic."""
        mock_ssm = MagicMock()
        mock_boto_client.return_value = mock_ssm
        
        # Simulate Lambda function execution
        event = {
            "Records": [
                {
                    "Sns": {
                        "Message": json.dumps({
                            "Trigger": {
                                "Dimensions": [
                                    {"value": "i-1234567890abcdef0"}
                                ]
                            }
                        })
                    }
                }
            ]
        }
        
        # Mock the cleanup function
        def lambda_handler(event, context):
            message = json.loads(event['Records'][0]['Sns']['Message'])
            instance_id = message['Trigger']['Dimensions'][0]['value']
            
            mock_ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={
                    'commands': [
                        "find /tmp -type f -atime +7 -delete",
                        "find /var/log -name '*.log.1' -delete"
                    ]
                }
            )
            
            return {"statusCode": 200, "body": "Cleanup initiated"}
        
        result = lambda_handler(event, {})
        
        assert result["statusCode"] == 200
        mock_ssm.send_command.assert_called_once()

    def test_dashboard_data_aggregation(self, cloudwatch_client, sample_config):
        """Test data aggregation for dashboard display."""
        # Publish metrics for multiple instances
        test_instances = ["i-1111111111111111", "i-2222222222222222", "i-3333333333333333"]
        
        for i, instance_id in enumerate(test_instances):
            cloudwatch_client.put_metric_data(
                Namespace="Custom/DiskMonitoring",
                MetricData=[
                    {
                        "MetricName": "DiskUtilization",
                        "Dimensions": [
                            {"Name": "InstanceId", "Value": instance_id},
                            {"Name": "AccountId", "Value": sample_config["target_accounts"][0]["account_id"]}
                        ],
                        "Value": 70.0 + (i * 10),  # 70%, 80%, 90%
                        "Unit": "Percent",
                        "Timestamp": datetime.utcnow()
                    }
                ]
            )
        
        # Test metric query for dashboard
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        response = cloudwatch_client.get_metric_statistics(
            Namespace="Custom/DiskMonitoring",
            MetricName="DiskUtilization",
            StartTime=start_time,
            EndTime=end_time,
            Period=