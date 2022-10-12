data "aws_caller_identity" "current" {}

resource "aws_iam_user_policy_attachment" "iam_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
  user = aws_iam_user.user.name
}

resource "aws_iam_user_policy_attachment" "manage_specific_credentials" {
  policy_arn = "arn:aws:iam::aws:policy/IAMSelfManageServiceSpecificCredentials"
  user = aws_iam_user.user.name
}

resource "aws_iam_user_policy_attachment" "manage_ssh_keys" {
  policy_arn = "arn:aws:iam::aws:policy/IAMUserSSHKeys"
  user = aws_iam_user.user.name
}

data "aws_iam_policy_document" "change_password" {
  statement {
    actions = [
      "iam:ChangePassword"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${var.user_name}"
    ]
    sid = "AllowUserToChangeTheirPassword"
  }
  statement {
    actions = [
    "iam:GetAccountPasswordPolicy"
    ]
    resources = [
      "*"
    ]
    sid = "AllowUserToViewPasswordPolicy"
  }
}

resource "aws_iam_user_policy" "change_password" {
  name = "IAMUserChangeOwnPassword"
  user = aws_iam_user.user.name
  policy = data.aws_iam_policy_document.change_password.json
}

data "aws_iam_policy_document" "manage_mfa" {
  statement {
    actions = [
      "iam:*MFADevice"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/${var.user_name}",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${var.user_name}"
    ]
    sid = "AllowUserToManageTheirMFA"
  }
}

resource "aws_iam_user_policy" "manage_mfa" {
  name = "IAMUserManageOwnMFA"
  user = aws_iam_user.user.name
  policy = data.aws_iam_policy_document.manage_mfa.json
}

data "aws_iam_policy_document" "manage_profile" {
  statement {
    actions = [
      "iam:*AccessKey*",
      "iam:*LoginProfile",
      "iam:*SigningCertificate*"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${var.user_name}"
    ]
    sid = "AllowUserToManageOwnProfile"
  }
}

resource "aws_iam_user_policy" "manage_profile" {
  name = "IAMUserManageOwnProfile"
  user = aws_iam_user.user.name
  policy = data.aws_iam_policy_document.manage_profile.json
}

data "aws_iam_policy_document" "enforce_mfa" {
  statement {
    condition {
      test = "BoolIfExists"
      values = ["false"]
      variable = "aws:MultiFactorAuthPresent"
    }
    effect = "Deny"
    not_actions = [
      "iam:*LoginProfile",
      "iam:*MFADevice",
      "iam:ChangePassword",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "iam:List*MFADevices",
      "iam:ListAccountAliases",
      "iam:ListUsers",
    ]
    resources = [
      "*",
    ]
    sid = "DenyEverythingOtherThanLoginManagementUnlessMFAd"
  }

  statement {
    condition {
      test = "BoolIfExists"
      values = ["false"]
      variable = "aws:MultiFactorAuthPresent"
    }
    effect = "Deny"
    actions = [
      "iam:*LoginProfile",
      "iam:*MFADevice",
      "iam:ChangePassword"
    ]
    not_resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/${var.user_name}",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${var.user_name}"
    ]
    sid = "DenyIAMAccessToOtherUsersUnlessMFAd"
  }
}

resource "aws_iam_user_policy" "enforce_mfa" {
  count = var.enforce_mfa == "yes" ? 1 : 0

  name = "EnforceMFA"
  policy = data.aws_iam_policy_document.enforce_mfa.json
  user = aws_iam_user.user.name
}
