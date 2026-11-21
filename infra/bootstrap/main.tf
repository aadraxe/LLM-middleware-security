data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # Account ID + region make S3 names globally unique without random suffixes.
  state_bucket   = "${var.project}-tfstate-${local.account_id}-${var.aws_region}"
  weights_bucket = "${var.project}-weights-${local.account_id}-${var.aws_region}"
  weights_prefix = "distilbert/"
}

# ── S3 buckets (state + model weights) ───────────────────────────────
module "state_bucket" {
  source                     = "./modules/private_bucket"
  name                       = local.state_bucket
  noncurrent_expiration_days = 90
}

module "weights_bucket" {
  source                     = "./modules/private_bucket"
  name                       = local.weights_bucket
  noncurrent_expiration_days = 30
}

# ── ECR repository ───────────────────────────────────────────────────
resource "aws_ecr_repository" "gateway" {
  name = var.project
  # Images are tagged with the git commit SHA; tags can never be overwritten.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true # basic scanning: free
  }

  encryption_configuration {
    encryption_type = "KMS" # AWS-managed aws/ecr key: no monthly key fee
  }
}

resource "aws_ecr_lifecycle_policy" "gateway" {
  repository = aws_ecr_repository.gateway.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Drop untagged layers/manifests after a day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the 10 most recent images (storage cost)"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      },
    ]
  })
}

# ── GitHub Actions OIDC ──────────────────────────────────────────────
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # No thumbprint: AWS validates GitHub's certificate chain itself.
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

locals {
  oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  # Exact `sub` claims GitHub issues for jobs without a deployment environment.
  sub_main         = "repo:${var.github_repository}:ref:refs/heads/main"
  sub_pull_request = "repo:${var.github_repository}:pull_request"
}

data "aws_iam_policy_document" "trust_build" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.sub_pull_request, local.sub_main]
    }
  }
}

data "aws_iam_policy_document" "trust_publish" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.sub_main]
    }
  }
}

data "aws_iam_policy_document" "read_weights" {
  statement {
    sid       = "ReadWeights"
    actions   = ["s3:GetObject"]
    resources = ["${module.weights_bucket.arn}/${local.weights_prefix}*"]
  }
  statement {
    sid       = "ListWeights"
    actions   = ["s3:ListBucket"]
    resources = [module.weights_bucket.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = [local.weights_prefix, "${local.weights_prefix}*"]
    }
  }
}

data "aws_iam_policy_document" "push_image" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"] # account-level API; cannot be scoped to a repository
    resources = ["*"]
  }
  statement {
    sid = "PushToGatewayRepository"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:DescribeImageScanFindings",
    ]
    resources = [aws_ecr_repository.gateway.arn]
  }
}

# PRs and main: read the weights to build and smoke-test the image. Nothing else.
resource "aws_iam_role" "ci_build" {
  name                 = "${var.project}-ci-build"
  description          = "GitHub Actions (${var.github_repository}, PRs and main): read model weights"
  assume_role_policy   = data.aws_iam_policy_document.trust_build.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "ci_build_weights" {
  name   = "read-weights"
  role   = aws_iam_role.ci_build.id
  policy = data.aws_iam_policy_document.read_weights.json
}

# main only: read the weights and push to the one ECR repository.
resource "aws_iam_role" "ci_publish" {
  name                 = "${var.project}-ci-publish"
  description          = "GitHub Actions (${var.github_repository}, main only): read weights, push gateway image"
  assume_role_policy   = data.aws_iam_policy_document.trust_publish.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "ci_publish_weights" {
  name   = "read-weights"
  role   = aws_iam_role.ci_publish.id
  policy = data.aws_iam_policy_document.read_weights.json
}

resource "aws_iam_role_policy" "ci_publish_ecr" {
  name   = "push-image"
  role   = aws_iam_role.ci_publish.id
  policy = data.aws_iam_policy_document.push_image.json
}
