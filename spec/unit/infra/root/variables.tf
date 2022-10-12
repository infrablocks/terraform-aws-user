variable "region" {}

variable "user_name" {}
variable "user_public_gpg_key_path" {}
variable "user_password_length" {
  type = number
  default = null
}
variable "enforce_mfa" {
  type = string
  default = null
}
variable "include_login_profile" {
  type = string
  default = null
}
variable "include_access_key" {
  type = string
  default = null
}
