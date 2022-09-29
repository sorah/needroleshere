#!/bin/bash 
while true; do
  aws sts get-caller-identity | jq -c .
  sleep 15
done
