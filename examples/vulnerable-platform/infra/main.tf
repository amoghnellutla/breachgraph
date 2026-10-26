# INTENTIONALLY INSECURE: demo target for breachgraph. Never apply.
provider "aws" {
  region = "us-east-1"
}

# The customer-data bucket is the crown jewel.
resource "aws_s3_bucket" "customer_data" {
  bucket = "shop-customer-data-prod"
  tags = {
    DataClassification = "pii"
  }
}

# The IAM role the EKS node group uses. hostNetwork pods inherit this via IMDS.
resource "aws_iam_role" "node" {
  name = "eks-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_eks_node_group" "main" {
  cluster_name  = "shop"
  node_role_arn = aws_iam_role.node.arn
  subnet_ids    = ["subnet-123"]
}

# Over-broad: node role can read every object in the customer-data bucket.
resource "aws_iam_role_policy" "node_s3" {
  role = aws_iam_role.node.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.customer_data.arn, "${aws_s3_bucket.customer_data.arn}/*"]
    }]
  })
}

# The pod role (IRSA) used by the api service account. Also over-broad.
resource "aws_iam_role" "api_pod" {
  name = "api-pod-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub" = "system:serviceaccount:shop:api"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "api_pod_admin" {
  role       = aws_iam_role.api_pod.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# CI deploy role, assumed by GitHub Actions over OIDC. The trust is scoped to the default branch,
# which looks safe, but issue_comment workflows run on the default branch too, so a comment that
# exploits script injection in triage.yml gets these credentials.
resource "aws_iam_role" "ci_deploy" {
  name = "ci-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:acme-shop/platform:ref:refs/heads/main" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci_deploy_reports" {
  role = aws_iam_role.ci_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["${aws_s3_bucket.customer_data.arn}/*"]
    }]
  })
}
