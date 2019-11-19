require 'spec_helper'
require 'uri'
require 'json'

describe 'policies' do
  let(:user_name) { vars.user_name }
  let(:user_arn) { output_for(:harness, 'user_arn') }

  let(:account_id) { account.account }

  subject {
    iam_user(user_name)
  }

  it { should have_iam_policy('IAMReadOnlyAccess') }
  it { should have_iam_policy('IAMSelfManageServiceSpecificCredentials') }
  it { should have_iam_policy('IAMUserSSHKeys') }

  it("allows managing MFA device without MFA in context") do
    expect(subject)
        .to(be_allowed_action('iam:*MFADevice')
            .resource_arn("arn:aws:iam::#{account_id}:mfa/#{vars.user_name}"))
    expect(subject)
        .to(be_allowed_action('iam:*MFADevice')
            .resource_arn(user_arn))
    expect(subject)
        .to(be_allowed_action('iam:List*MFADevices')
            .resource_arn('*'))
  end

  it("allows managing user profile without MFA in context") do
    expect(subject)
        .to(be_allowed_action('iam:*LoginProfile')
            .resource_arn(user_arn))
  end

  it('requires MFA in context to manage access keys and signing certs') do
    mfa_context = {
        context_key_name: "aws:MultiFactorAuthPresent",
        context_key_values: ["true"],
        context_key_type: "boolean"
    }
    expect(subject)
        .not_to(be_allowed_action('iam:*AccessKey*')
            .resource_arn(user_arn))
    expect(subject)
        .not_to(be_allowed_action('iam:*SigningCertificate*')
            .resource_arn(user_arn))
    expect(subject)
        .to(be_allowed_action('iam:*AccessKey*')
            .resource_arn(user_arn)
            .context_entries([mfa_context]))
    expect(subject)
        .to(be_allowed_action('iam:*SigningCertificate*')
            .resource_arn(user_arn)
            .context_entries([mfa_context]))
  end

  it('allows changing password without MFA in context') do
    expect(subject)
        .to(be_allowed_action('iam:GetAccountPasswordPolicy'))
    expect(subject)
        .to(be_allowed_action('iam:ChangePassword')
            .resource_arn(user_arn))
  end

  it('allows getting account summary without MFA in context') do
    expect(subject).to(be_allowed_action('iam:GetAccountSummary'))
  end

  it('allows users to be listed without MFA in context') do
    expect(subject).to(be_allowed_action('iam:ListUsers'))
  end

  it('allows account aliases to be listed without MFA in context') do
    expect(subject).to(be_allowed_action('iam:ListAccountAliases'))
  end
end
