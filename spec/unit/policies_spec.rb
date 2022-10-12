# frozen_string_literal: true

require 'spec_helper'
require 'uri'
require 'json'

describe 'policies' do
  let(:iam_read_only_access_policy_arn) do
    'arn:aws:iam::aws:policy/IAMReadOnlyAccess'
  end
  let(:iam_self_manage_service_specific_credentials_policy_arn) do
    'arn:aws:iam::aws:policy/IAMSelfManageServiceSpecificCredentials'
  end
  let(:iam_user_ssh_keys_policy_arn) do
    'arn:aws:iam::aws:policy/IAMUserSSHKeys'
  end

  describe 'by default' do
    before(:context) do
      client = Aws::STS::Client.new
      caller_id = client.get_caller_identity
      @account_id = caller_id.account

      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
      end
    end

    it 'creates a policy attachment for IAM read only access for the user' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy_attachment'
        )
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy_arn, iam_read_only_access_policy_arn
              ))
    end

    it 'creates a policy attachment for for managing IAM credentials ' \
       'for the user' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy_attachment'
        )
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy_arn,
                iam_self_manage_service_specific_credentials_policy_arn
              ))
    end

    it 'creates a policy attachment for IAM SSH keys ' \
       'for the user' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy_attachment'
        )
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy_arn,
                iam_user_ssh_keys_policy_arn
              ))
    end

    it 'creates a user policy allowing the user to change their password' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy'
        )
              .with_attribute_value(:name, 'IAMUserChangeOwnPassword')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy,
                a_policy_with_statement(
                  Effect: 'Allow',
                  Action: 'iam:ChangePassword',
                  Resource:
                    "arn:aws:iam::#{@account_id}:user/test@example.com"
                )
              ))
    end

    it 'creates a user policy allowing the user to manage their own ' \
       'profile' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy'
        )
              .with_attribute_value(:name, 'IAMUserManageOwnProfile')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy,
                a_policy_with_statement(
                  Effect: 'Allow',
                  Action: %w[
                    iam:*AccessKey*
                    iam:*LoginProfile
                    iam:*SigningCertificate*
                  ],
                  Resource:
                    "arn:aws:iam::#{@account_id}:user/test@example.com"
                )
              ))
    end

    it 'creates a user policy allowing the user to manage their own MFA' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy'
        )
              .with_attribute_value(:name, 'IAMUserManageOwnMFA')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy,
                a_policy_with_statement(
                  Effect: 'Allow',
                  Action: 'iam:*MFADevice',
                  Resource: %W[
                    arn:aws:iam::#{@account_id}:mfa/test@example.com
                    arn:aws:iam::#{@account_id}:user/test@example.com
                  ]
                )
              ))
    end
  end

  describe 'when user should have MFA enforced' do
    before(:context) do
      client = Aws::STS::Client.new
      caller_id = client.get_caller_identity
      @account_id = caller_id.account

      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
        vars.enforce_mfa = 'yes'
      end
    end

    it 'creates a user policy preventing the user from doing anything ' \
       'other than manage their own IAM when the session was not ' \
       'established using MFA' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy'
        )
              .with_attribute_value(:name, 'EnforceMFA')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy,
                a_policy_with_statement(
                  Effect: 'Deny',
                  NotAction: %w[
                    iam:*LoginProfile
                    iam:*MFADevice
                    iam:ChangePassword
                    iam:GetAccountPasswordPolicy
                    iam:GetAccountSummary
                    iam:List*MFADevices
                    iam:ListAccountAliases
                    iam:ListUsers
                  ],
                  Resource: '*',
                  Condition: {
                    BoolIfExists: {
                      'aws:MultiFactorAuthPresent': 'false'
                    }
                  }
                )
              ))
    end

    it 'creates a user policy preventing the user from managing ' \
       'other users IAM credentials when the session was not ' \
       'established using MFA' do
      expect(@plan)
        .to(include_resource_creation(
          type: 'aws_iam_user_policy'
        )
              .with_attribute_value(:name, 'EnforceMFA')
              .with_attribute_value(:user, 'test@example.com')
              .with_attribute_value(
                :policy,
                a_policy_with_statement(
                  Effect: 'Deny',
                  Action: %w[
                    iam:*LoginProfile
                    iam:*MFADevice
                    iam:ChangePassword
                  ],
                  NotResource: %W[
                    arn:aws:iam::#{@account_id}:mfa/test@example.com
                    arn:aws:iam::#{@account_id}:user/test@example.com
                  ],
                  Condition: {
                    BoolIfExists: {
                      'aws:MultiFactorAuthPresent': 'false'
                    }
                  }
                )
              ))
    end
  end

  describe 'when user should not have MFA enforced' do
    before(:context) do
      client = Aws::STS::Client.new
      caller_id = client.get_caller_identity
      @account_id = caller_id.account

      @plan = plan(role: :root) do |vars|
        vars.user_name = 'test@example.com'
        vars.enforce_mfa = 'no'
      end
    end

    it 'does not create a user policy preventing the user from doing ' \
       'anything other than manage their own IAM when the session was not ' \
       'established using MFA' do
      expect(@plan)
        .not_to(include_resource_creation(
          type: 'aws_iam_user_policy'
        )
                  .with_attribute_value(:name, 'EnforceMFA')
                  .with_attribute_value(:user, 'test@example.com')
                  .with_attribute_value(
                    :policy,
                    a_policy_with_statement(
                      Effect: 'Deny',
                      NotAction: %w[
                        iam:*LoginProfile
                        iam:*MFADevice
                        iam:ChangePassword
                        iam:GetAccountPasswordPolicy
                        iam:GetAccountSummary
                        iam:List*MFADevices
                        iam:ListAccountAliases
                        iam:ListUsers
                      ],
                      Resource: '*',
                      Condition: {
                        BoolIfExists: {
                          'aws:MultiFactorAuthPresent': 'false'
                        }
                      }
                    )
                  ))
    end

    it 'does not create a user policy preventing the user from managing ' \
       'other users IAM credentials when the session was not ' \
       'established using MFA' do
      expect(@plan)
        .not_to(include_resource_creation(
          type: 'aws_iam_user_policy'
        )
                  .with_attribute_value(:name, 'EnforceMFA')
                  .with_attribute_value(:user, 'test@example.com')
                  .with_attribute_value(
                    :policy,
                    a_policy_with_statement(
                      Effect: 'Deny',
                      Action: %w[
                        iam:*LoginProfile
                        iam:*MFADevice
                        iam:ChangePassword
                      ],
                      NotResource: %W[
                        arn:aws:iam::#{@account_id}:mfa/test@example.com
                        arn:aws:iam::#{@account_id}:user/test@example.com
                      ],
                      Condition: {
                        BoolIfExists: {
                          'aws:MultiFactorAuthPresent': 'false'
                        }
                      }
                    )
                  ))
    end
  end
end
