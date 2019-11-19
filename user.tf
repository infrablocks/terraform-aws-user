resource "aws_iam_user" "user" {
  name = var.user_name
  force_destroy = true
}

resource "aws_iam_user_login_profile" "user" {
  count = var.include_login_profile == "yes" ? 1 : 0

  user = aws_iam_user.user.name
  pgp_key = var.user_public_gpg_key
  password_length = var.user_password_length
}

resource "aws_iam_access_key" "user" {
  count = var.include_access_key == "yes" ? 1 : 0

  user = aws_iam_user.user.name
  pgp_key = var.user_public_gpg_key
}
