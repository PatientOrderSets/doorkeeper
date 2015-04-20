require 'spec_helper_integration'

class TestResourceOwnerService
  def self.retrieve(payload)
    User.where(name: payload['sub']).first
  end
end

describe 'JWT Credentials Flow' do
  before :each do
    config_is_set(:client_credentials, :from_jwt)
    config_is_set(:grant_flows, [Doorkeeper::Request::Jwt::GRANT_TYPE])
    config_is_set(:resource_owner_from_jwt, "TestResourceOwnerService")
    create_resource_owner
    client_exists
  end

  context 'when the configuration is not setup properly' do
    before :each do
      config_is_set(:client_credentials, [:from_params])
      config_is_set(:grant_flows, [Doorkeeper::Request::Jwt::GRANT_TYPE])
      config_is_set(:resource_owner_from_jwt, "TestResourceOwnerService")
    end

    it 'will not issue a token' do
      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end
  end

  context 'with valid user credentials' do
    before :each do
      create_assertion(@client, @resource_owner)
    end

    it 'should issue new token' do
      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to change { Doorkeeper::AccessToken.count }.by(1)

      token = Doorkeeper::AccessToken.first

      should_have_json 'access_token',  token.token
    end

    it 'should issue a refresh token if enabled' do
      config_is_set(:refresh_token_enabled, true)

      post jwt_token_endpoint_url(assertion: @assertion)

      token = Doorkeeper::AccessToken.first

      should_have_json 'refresh_token',  token.refresh_token
    end

    it 'should return the same token if it is still accessible' do
      expect(Doorkeeper.configuration).to receive(:reuse_access_token).and_return(true)

      client_is_authorized(@client, @resource_owner)

      post jwt_token_endpoint_url(assertion: @assertion)

      expect(Doorkeeper::AccessToken.count).to eq(1)
      should_have_json 'access_token', Doorkeeper::AccessToken.first.token
    end
  end

  context 'with an invalid assertion' do
    it 'should not issue new token with an unknown resource_owner' do
      create_assertion(@client, @resource_owner, {'sub' => 'some dude'})

      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end

    it 'should not issue new token with an invalid iss' do
      create_assertion(@client, @resource_owner, {'iss' => 'unknown'})

      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end

    it 'should not issue new token with expired assertion' do
      five_minutes_in_sec = 5 * 60
      create_assertion(@client, @resource_owner, {'exp' => (Time.now - five_minutes_in_sec).to_i})
      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end

    it 'should not issue new token with expired assertion' do
      create_assertion(@client, @resource_owner, {}, 'other_secret')
      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end
  end
end
