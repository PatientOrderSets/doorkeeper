module ModelHelper
  def client_exists(client_attributes = {})
    @client = FactoryGirl.create(:application, client_attributes)
  end

  def create_resource_owner
    @resource_owner = User.create!(name: 'Joe', password: 'sekret')
  end

  def create_assertion(client, resource_owner, claims = {}, secret = nil)
    combined_claims = build_claims({'iss' => client.uid, 'sub' => resource_owner.name}.merge(claims))
    secret ||= client.secret

    @assertion = ::JWT.encode(combined_claims, secret, 'HS256')
  end

  def build_claims(claims = {})
    five_minutes_in_sec = 5 * 60

    default_claims =
        {
            'iss' => 'some_client_id',
            'aud' => 'http://www.thirdparty.com',
            'sub' => 'some_resource_unique_identifier',
            'exp' => (Time.now + five_minutes_in_sec).to_i
        }

    default_claims.merge(claims)
  end

  def authorization_code_exists(options = {})
    @authorization = FactoryGirl.create(:access_grant, options)
  end

  def access_grant_should_exist_for(client, resource_owner)
    grant = Doorkeeper::AccessGrant.first
    expect(grant.application).to eq(client)
    grant.resource_owner_id  == resource_owner.id
  end

  def access_token_should_exist_for(client, resource_owner)
    grant = Doorkeeper::AccessToken.first
    expect(grant.application).to eq(client)
    grant.resource_owner_id  == resource_owner.id
  end

  def access_grant_should_not_exist
    expect(Doorkeeper::AccessGrant.all).to be_empty
  end

  def access_token_should_not_exist
    expect(Doorkeeper::AccessToken.all).to be_empty
  end

  def access_grant_should_have_scopes(*args)
    grant = Doorkeeper::AccessGrant.first
    expect(grant.scopes).to eq(Doorkeeper::OAuth::Scopes.from_array(args))
  end

  def access_token_should_have_scopes(*args)
    grant = Doorkeeper::AccessToken.last
    expect(grant.scopes).to eq(Doorkeeper::OAuth::Scopes.from_array(args))
  end
end

RSpec.configuration.send :include, ModelHelper, type: :request
