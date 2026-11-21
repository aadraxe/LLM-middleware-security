output "aws_region" {
  value = var.aws_region
}

output "state_bucket" {
  description = "Backend bucket for infra/app."
  value       = module.state_bucket.name
}

output "weights_bucket" {
  value = module.weights_bucket.name
}

output "weights_s3_uri" {
  value = "s3://${module.weights_bucket.name}/${local.weights_prefix}"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.gateway.repository_url
}

output "ci_build_role_arn" {
  description = "GitHub variable AWS_CI_BUILD_ROLE_ARN (PRs and main)."
  value       = aws_iam_role.ci_build.arn
}

output "ci_publish_role_arn" {
  description = "GitHub variable AWS_CI_PUBLISH_ROLE_ARN (main only)."
  value       = aws_iam_role.ci_publish.arn
}
