locals {
  public_gpg_key = filebase64(var.public_gpg_key_path)

}

module "user" {
  source = "../../"

  user_name = "test.${var.deployment_identifier}@example.com"
  user_password_length = 48
  user_public_gpg_key = local.public_gpg_key
  enforce_mfa = "yes"
  include_login_profile = "yes"
  include_access_key = "yes"
}
