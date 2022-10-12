data "terraform_remote_state" "prerequisites" {
  backend = "local"

  config = {
    path = "${path.module}/../../../../state/prerequisites.tfstate"
  }
}

module "user" {
  source = "../../../.."

  user_name = var.user_name
  user_public_gpg_key = filebase64(var.user_public_gpg_key_path)
  user_password_length = var.user_password_length
  enforce_mfa = var.enforce_mfa
  include_login_profile = var.include_login_profile
  include_access_key = var.include_access_key
}
