#!/bin/bash
echo "Setting up environment..."
python3 -m venv venv
source venv/bin/activate
pip install ansible boto boto3
echo "Environment ready."
