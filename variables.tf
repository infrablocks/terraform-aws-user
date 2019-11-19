variable "user_name" {
  type = string
  description = "The name of the user to create."
}

variable "user_public_gpg_key" {
  type = string
  default = ""
  description = "The contents of the public GPG key for the user, base 64 encoded. Only required if 'include_login_profile' or 'include_access_key' are true."
}

variable "user_password_length" {
  type = number
  default = 32
  description = "The length of the user password to create. Only required if 'include_login_profile' is true."
}

variable "include_login_profile" {
  default = true
  type = bool
  description = "Whether or not to generate a login profile for the user. Uses the provided GPG key to encrypt the credentials. Defaults to true."
}

variable "include_access_key" {
  default = true
  type = bool
  description = "Whether or not to generate an access key for the user. Uses the provided GPG key to encrypt the credentials. Defaults to true."
}
