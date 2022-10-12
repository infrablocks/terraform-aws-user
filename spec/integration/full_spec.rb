# frozen_string_literal: true

require 'spec_helper'

describe 'full' do
  before(:context) do
    apply(role: :full)
  end

  after(:context) do
    destroy(role: :full)
  end

  let(:account_id) { account.account }

  let(:deployment_identifier) do
    var(role: :full, name: 'deployment_identifier')
  end

  let(:gpg_key_passphrase) do
    File.read('config/secrets/user/gpg.passphrase')
  rescue StandardError
    nil
  end

  let(:private_gpg_key) do
    File.read('config/secrets/user/gpg.private')
  rescue StandardError
    nil
  end

  # rubocop:disable RSpec/MultipleExpectations
  it 'creates a user' do
    created_user = iam_user("test.#{deployment_identifier}@example.com")
    output_user_arn = output(role: :full, name: 'user_arn')

    expect(created_user).to(exist)
    expect(created_user.arn).to(eq(output_user_arn))
  end
  # rubocop:enable RSpec/MultipleExpectations

  it 'creates a login profile for the user using the provided GPG key' do
    output_password = output(role: :full, name: 'user_password')
    encrypted_password = StringIO.new(Base64.decode64(output_password))

    IOStreams::Pgp.import(key: private_gpg_key)
    password = IOStreams::Pgp::Reader
               .open(encrypted_password,
                     passphrase: gpg_key_passphrase) do |stdout|
      stdout.read.chomp
    end

    expect(password&.length).to(eq(48))
  end

  # rubocop:disable RSpec/MultipleExpectations
  it 'creates an access key for the user using the provided GPG key' do
    output_access_key_id =
      output(role: :full, name: 'user_access_key_id')
    output_secret_access_key =
      output(role: :full, name: 'user_secret_access_key')
    encrypted_secret_access_key =
      StringIO.new(Base64.decode64(output_secret_access_key))

    IOStreams::Pgp.import(key: private_gpg_key)
    secret_access_key =
      IOStreams::Pgp::Reader
      .open(encrypted_secret_access_key,
            passphrase: gpg_key_passphrase) do |stdout|
        stdout.read.chomp
      end

    expect(output_access_key_id.length).to(be(20))
    expect(secret_access_key&.length).to(be(40))
  end
  # rubocop:enable RSpec/MultipleExpectations

  it 'allows the user IAM read only access' do
    created_user = iam_user("test.#{deployment_identifier}@example.com")

    expect(created_user).to(have_iam_policy('IAMReadOnlyAccess'))
  end

  it 'allows the user to manage service specific credentials' do
    created_user = iam_user("test.#{deployment_identifier}@example.com")

    expect(created_user)
      .to(have_iam_policy('IAMSelfManageServiceSpecificCredentials'))
  end

  it 'allows the user to manage their own SSH keys' do
    created_user = iam_user("test.#{deployment_identifier}@example.com")

    expect(created_user).to(have_iam_policy('IAMUserSSHKeys'))
  end

  # rubocop:disable RSpec/MultipleExpectations
  it 'allows the user to manage their MFA device without MFA in context' do
    user_name = "test.#{deployment_identifier}@example.com"
    created_user = iam_user(user_name)

    expect(created_user)
      .to(be_allowed_action('iam:*MFADevice')
            .resource_arn("arn:aws:iam::#{account_id}:mfa/#{user_name}"))
    expect(created_user)
      .to(be_allowed_action('iam:*MFADevice')
            .resource_arn(created_user.arn))
    expect(created_user)
      .to(be_allowed_action('iam:List*MFADevices')
            .resource_arn('*'))
  end
  # rubocop:enable RSpec/MultipleExpectations

  it 'allows the user to manage their profile without MFA in context' do
    user_name = "test.#{deployment_identifier}@example.com"
    created_user = iam_user(user_name)

    expect(created_user)
      .to(be_allowed_action('iam:*LoginProfile')
            .resource_arn(created_user.arn))
  end

  # rubocop:disable RSpec/MultipleExpectations
  it 'requires MFA in context for the user to manage access keys and ' \
     'signing certs' do
    user_name = "test.#{deployment_identifier}@example.com"
    created_user = iam_user(user_name)
    mfa_context = {
      context_key_name: 'aws:MultiFactorAuthPresent',
      context_key_values: ['true'],
      context_key_type: 'boolean'
    }
    expect(created_user)
      .not_to(be_allowed_action('iam:*AccessKey*')
            .resource_arn(created_user.arn))
    expect(created_user)
      .not_to(be_allowed_action('iam:*SigningCertificate*')
            .resource_arn(created_user.arn))
    expect(created_user)
      .to(be_allowed_action('iam:*AccessKey*')
            .resource_arn(created_user.arn)
            .context_entries([mfa_context]))
    expect(created_user)
      .to(be_allowed_action('iam:*SigningCertificate*')
            .resource_arn(created_user.arn)
            .context_entries([mfa_context]))
  end
  # rubocop:enable RSpec/MultipleExpectations

  # rubocop:disable RSpec/MultipleExpectations
  it 'allows the user to change their password without MFA in context' do
    user_name = "test.#{deployment_identifier}@example.com"
    created_user = iam_user(user_name)

    expect(created_user)
      .to(be_allowed_action('iam:GetAccountPasswordPolicy'))
    expect(created_user)
      .to(be_allowed_action('iam:ChangePassword')
            .resource_arn(created_user.arn))
  end
  # rubocop:enable RSpec/MultipleExpectations

  it('allows the user to get the account summary without MFA in context') do
    user_name = "test.#{deployment_identifier}@example.com"
    created_user = iam_user(user_name)

    expect(created_user).to(be_allowed_action('iam:GetAccountSummary'))
  end

  it('allows the user to list other users without MFA in context') do
    user_name = "test.#{deployment_identifier}@example.com"
    created_user = iam_user(user_name)

    expect(created_user).to(be_allowed_action('iam:ListUsers'))
  end

  it('allows the user to list account aliases without MFA in context') do
    user_name = "test.#{deployment_identifier}@example.com"
    created_user = iam_user(user_name)

    expect(created_user).to(be_allowed_action('iam:ListAccountAliases'))
  end
end
