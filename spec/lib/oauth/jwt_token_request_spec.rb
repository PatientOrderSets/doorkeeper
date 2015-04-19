require 'spec_helper_integration'

module Doorkeeper::OAuth
  describe JwtTokenRequest do
    let(:server) do
      double(
        :server,
        default_scopes: Doorkeeper::OAuth::Scopes.new,
        access_token_expires_in: 2.hours,
        refresh_token_enabled?: false,
        resource_owner_from_jwt: "Doorkeeper::OAuth::StubResourceOwnerFromJwt",
        custom_access_token_expires_in: ->(_app) { nil }
      )
    end
    let(:client) { FactoryGirl.create(:application) }
    let(:credentials) { Client::Credentials.new(client.uid, client.secret) }
    let(:owner)  { double :owner, id: 99 }

    let(:five_minutes_in_sec) { 5 * 60 }
    let(:encryption_method) { 'HS256' }
    let(:valid_jwt_hash) do
      {
          'iss' => client.uid,
          'aud' => 'http://www.thirdparty.com',
          'sub' => 'user@localsystem.com',
          'exp' => (Time.now + five_minutes_in_sec).to_i
      }
    end

    let(:assertion) do
      ::JWT.encode(valid_jwt_hash, client.secret, encryption_method)
    end

    let(:invalid_assertion) do
      ::JWT.encode(valid_jwt_hash, 'other secret', encryption_method)
    end

    class StubResourceOwnerFromJwt
      def self.retrieve(payload)
        OpenStruct.new(id: 99)
      end
    end

    context 'when initializing the JwtTokenRequest' do
      subject do
        JwtTokenRequest
      end

      it 'will set the resource_owner with valid assertion' do
        request = subject.new(server, credentials, assertion: assertion)

        expect(request.resource_owner.id).to eq(owner.id)
      end

      it 'will not set the resource_owner when an assertion is invalid' do
        request = subject.new(server, credentials, assertion: invalid_assertion)

        expect(request.resource_owner).to be_nil
      end

      it 'will not set the resource_owner when no credentials are provided' do
        request = subject.new(server, nil, assertion: invalid_assertion)

        expect(request.resource_owner).to be_nil
      end
    end

    context 'when processing a request' do
      subject do
        JwtTokenRequest.new(server, credentials, assertion: assertion)
      end

      it 'issues a new token for the client' do
        expect do
          subject.authorize
        end.to change { client.access_tokens.count }.by(1)
      end

      it 'issues a new token without credentials set but has client' do
        expect do
          subject.credentials = nil
          subject.authorize
        end.to change { Doorkeeper::AccessToken.count }.by(1)
      end

      it 'does not issue a new token with an invalid client' do
        expect do
          subject.client = nil
          subject.authorize
        end.to_not change { Doorkeeper::AccessToken.count }

        expect(subject.error).to eq(:invalid_client)
      end

      it 'does not issue a token with invalid assertion' do
        expect do
          subject.assertion = invalid_assertion
          subject.authorize
        end.to_not change { Doorkeeper::AccessToken.count }

        expect(subject.error).to eq(:invalid_jwt)
      end

      it 'requires the owner' do
        subject.resource_owner = nil
        subject.validate
        expect(subject.error).to eq(:invalid_grant)
      end

      it 'optionally accepts the client' do
        subject.credentials = nil
        expect(subject).to be_valid
      end

      it 'creates token even when there is already one (default)' do
        FactoryGirl.create(:access_token, application_id: client.id, resource_owner_id: owner.id)
        expect do
          subject.authorize
        end.to change { Doorkeeper::AccessToken.count }.by(1)
      end

      it 'skips token creation if there is already one' do
        Doorkeeper.configuration.stub(:reuse_access_token).and_return(true)
        FactoryGirl.create(:access_token, application_id: client.id, resource_owner_id: owner.id)
        expect do
          subject.authorize
        end.to_not change { Doorkeeper::AccessToken.count }
      end

      describe 'with scopes' do
        subject do
          JwtTokenRequest.new(server, client, assertion: assertion, scope: 'public')
        end

        it 'validates the current scope' do
          allow(server).to receive(:scopes).and_return(Doorkeeper::OAuth::Scopes.from_string('another'))
          subject.validate
          expect(subject.error).to eq(:invalid_scope)
        end

        it 'creates the token with scopes' do
          allow(server).to receive(:scopes).and_return(Doorkeeper::OAuth::Scopes.from_string('public'))
          expect do
            subject.authorize
          end.to change { Doorkeeper::AccessToken.count }.by(1)
          expect(Doorkeeper::AccessToken.last.scopes).to include('public')
        end
      end
    end
  end
end
