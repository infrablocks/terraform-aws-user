data "terraform_remote_state" "prerequisites" {
  backend = "local"

  config = {
    path = "${path.module}/../../../../state/prerequisites.tfstate"
  }
}

module "user" {
  # This makes absolutely no sense. I think there's a bug in terraform.
  source = "./../../../../../../../"

  user_name = var.user_name
  user_public_gpg_key = filebase64(var.user_public_gpg_key_path)
}
