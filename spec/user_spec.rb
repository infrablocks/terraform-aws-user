require 'spec_helper'
require 'iostreams'

require_relative 'iostreams/pgp'

describe 'user' do
  let(:user_name) { vars.user_name }
  let(:user_arn) { output_for(:harness, 'user_arn') }

  subject {
    iam_user(user_name)
  }

  it { should exist }
  its(:arn) { should eq(user_arn) }

  it 'outputs username and GPG encrypted login password' do
    username = output_for(:harness, 'user_name')
    encrypted_password =
        StringIO.new(
            Base64.decode64(
                output_for(:harness, 'user_password')))

    passphrase = configuration.gpg_key_passphrase
    private_key = File.read(configuration.private_gpg_key_path)

    IOStreams::Pgp.import(key: private_key)
    password = IOStreams::Pgp::Reader
        .open(encrypted_password, passphrase: passphrase) do |stdout|
      stdout.read.chomp
    end

    expect(username).to(eq(vars.user_name))
    expect(password.length).to(be(32))
  end

  it 'outputs access key ID and secret access key' do
    access_key_id = output_for(:harness, 'user_access_key_id')
    encrypted_secret_access_key =
        StringIO.new(
            Base64.decode64(
                output_for(:harness, 'user_secret_access_key')))

    passphrase = configuration.gpg_key_passphrase
    private_key = File.read(configuration.private_gpg_key_path)

    IOStreams::Pgp.import(key: private_key)
    secret_access_key = IOStreams::Pgp::Reader
        .open(encrypted_secret_access_key, passphrase: passphrase) do |stdout|
      stdout.read.chomp
    end

    expect(access_key_id.length).to(be(20))
    expect(secret_access_key.length).to(be(40))
  end
end
