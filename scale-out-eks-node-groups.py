import boto3
import json
import os

def lambda_handler(event, context):
    eks_client = boto3.client('eks')

    json_file_path = os.environ['JSON_FILE_PATH']

    try:
        # Read the JSON file
        with open(json_file_path, 'r') as file:
            cluster_nodegroups = json.load(file)

        # Iterate over each cluster and its node groups
        for cluster_name, nodegroups in cluster_nodegroups.items():
            for nodegroup in nodegroups:
                for nodegroup_name, max_size in nodegroup.items():
                    try:
                        response = eks_client.update_nodegroup_config(
                            clusterName=cluster_name,
                            nodegroupName=nodegroup_name,
                            scalingConfig={
                                'maxSize': max_size
                            }
                        )
                        print(f"Successfully updated max size of node group '{nodegroup_name}' in cluster '{cluster_name}' to {max_size}")
                    except Exception as e:
                        print(f"Failed to update node group '{nodegroup_name}' in cluster '{cluster_name}': {str(e)}")

        return {
            'statusCode': 200,
            'body': "Successfully updated all specified node groups."
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': f"Error processing node group updates: {str(e)}"
        }
