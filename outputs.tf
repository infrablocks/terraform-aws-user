output "user_arn" {
  value = aws_iam_user.user.arn
}

output "user_name" {
  value = var.user_name
}

output "user_password" {
  value = element(concat(aws_iam_user_login_profile.user.*.encrypted_password, [""]), 0)
}

output "user_access_key_id" {
  value = element(concat(aws_iam_access_key.user.*.id, [""]), 0)
}

output "user_secret_access_key" {
  value = element(concat(aws_iam_access_key.user.*.encrypted_secret, [""]), 0)
}
