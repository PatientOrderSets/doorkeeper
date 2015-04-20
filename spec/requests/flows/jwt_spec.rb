require 'spec_helper_integration'

class TestResourceOwnerService
  def self.retrieve(payload)
    User.find_by(name: payload['sub'])
  end
end

feature 'JWT Credentials Flow' do
  background do
    config_is_set(:client_credentials, :from_jwt)
    config_is_set(:grant_flows, [Doorkeeper::Request::Jwt::GRANT_TYPE])
    config_is_set(:resource_owner_from_jwt, "TestResourceOwnerService")
    client_exists
    create_resource_owner
  end

  context 'with valid user credentials' do
    before :each do
      create_assertion(@client, @resource_owner)
    end

    scenario 'should issue new token' do
      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to change { Doorkeeper::AccessToken.count }.by(1)

      token = Doorkeeper::AccessToken.first

      should_have_json 'access_token',  token.token
    end

    scenario 'should issue a refresh token if enabled' do
      config_is_set(:refresh_token_enabled, true)

      post jwt_token_endpoint_url(assertion: @assertion)

      token = Doorkeeper::AccessToken.first

      should_have_json 'refresh_token',  token.refresh_token
    end

    scenario 'should return the same token if it is still accessible' do
      Doorkeeper.configuration.stub(:reuse_access_token).and_return(true)

      client_is_authorized(@client, @resource_owner)

      post jwt_token_endpoint_url(assertion: @assertion)

      Doorkeeper::AccessToken.count.should be(1)
      should_have_json 'access_token', Doorkeeper::AccessToken.first.token
    end
  end

  context 'with an invalid assertion' do
    scenario 'should not issue new token with an unknown resource_owner' do
      create_assertion(@client, @resource_owner, {'sub' => 'some dude'})

      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end

    scenario 'should not issue new token with an invalid iss' do
      create_assertion(@client, @resource_owner, {'iss' => 'unknown'})

      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end

    scenario 'should not issue new token with expired assertion' do
      five_minutes_in_sec = 5 * 60
      create_assertion(@client, @resource_owner, {'exp' => (Time.now - five_minutes_in_sec).to_i})
      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end

    scenario 'should not issue new token with expired assertion' do
      create_assertion(@client, @resource_owner, {}, 'other_secret')
      expect do
        post jwt_token_endpoint_url(assertion: @assertion)
      end.to_not change { Doorkeeper::AccessToken.count }
    end
  end
end
