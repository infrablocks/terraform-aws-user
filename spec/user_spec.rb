require 'spec_helper'

describe 'user' do
  let(:user_name) { vars.user_name }
  let(:user_arn) { output_for(:harness, 'user_arn') }

  subject {
    iam_user(user_name)
  }

  it { should exist }
  its(:arn) { should eq(user_arn) }
end
