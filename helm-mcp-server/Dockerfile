FROM sandeep2014/talkops-mcp:helm-mcp-server-latest

USER root

# Install AWS CLI v2 (required for EKS kubeconfig auth via `aws eks get-token`)
RUN apt-get update && \
    apt-get install -y --no-install-recommends unzip && \
    curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip && \
    unzip -q /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install && \
    rm -rf /tmp/aws /tmp/awscliv2.zip /var/lib/apt/lists/*

USER app
