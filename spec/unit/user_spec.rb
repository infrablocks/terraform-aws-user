# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'
require 'base64'

describe 'user' do
  describe 'by default' do
    before(:context) do
      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
      end
    end

    it 'creates a user' do
      expect(@plan)
        .to(include_resource_creation(type: 'aws_iam_user')
              .with_attribute_value(:name, 'test@example.com'))
    end

    it 'enables force destroy for the created user' do
      expect(@plan)
        .to(include_resource_creation(type: 'aws_iam_user')
              .with_attribute_value(:name, 'test@example.com')
              .with_attribute_value(:force_destroy, true))
    end
  end

  describe 'when login profile included' do
    before(:context) do
      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
        vars.user_password_length = 48
        vars.include_login_profile = 'yes'
      end
    end

    it 'creates a login profile for the user' do
      expect(@plan)
        .to(include_resource_creation(type: 'aws_iam_user_login_profile')
              .with_attribute_value(:user, 'test@example.com'))
    end

    it 'uses the specified password length' do
      expect(@plan)
        .to(include_resource_creation(type: 'aws_iam_user_login_profile')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(:password_length, 48))
    end

    it 'uses the specified public GPG key' do
      public_gpg_key_path = var(role: :root, name: 'user_public_gpg_key_path')
      public_gpg_key = Base64.strict_encode64(File.read(public_gpg_key_path))

      expect(@plan)
        .to(include_resource_creation(type: 'aws_iam_user_login_profile')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(:pgp_key, public_gpg_key))
    end
  end

  describe 'when login profile not included' do
    before(:context) do
      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
        vars.user_password_length = 48
        vars.include_login_profile = 'no'
      end
    end

    it 'does not create a login profile for the user' do
      expect(@plan)
        .not_to(include_resource_creation(type: 'aws_iam_user_login_profile')
                  .with_attribute_value(:user, 'test@example.com'))
    end
  end

  describe 'when access key included' do
    before(:context) do
      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
        vars.include_access_key = 'yes'
      end
    end

    it 'creates an access key for the user' do
      expect(@plan)
        .to(include_resource_creation(type: 'aws_iam_access_key')
              .with_attribute_value(:user, 'test@example.com'))
    end

    it 'uses the specified public GPG key' do
      public_gpg_key_path = var(role: :root, name: 'user_public_gpg_key_path')
      public_gpg_key = Base64.strict_encode64(File.read(public_gpg_key_path))

      expect(@plan)
        .to(include_resource_creation(type: 'aws_iam_access_key')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(:pgp_key, public_gpg_key))
    end
  end

  describe 'when access key not included' do
    before(:context) do
      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
        vars.include_access_key = 'no'
      end
    end

    it 'does not create an access key for the user' do
      expect(@plan)
        .not_to(include_resource_creation(type: 'aws_iam_access_key')
                  .with_attribute_value(:user, 'test@example.com'))
    end
  end
end
