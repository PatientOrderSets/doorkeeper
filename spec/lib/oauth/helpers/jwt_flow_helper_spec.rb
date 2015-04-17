require 'spec_helper_integration'
require 'doorkeeper/oauth/helpers/jwt_flow_helper'
require 'jwt'


module Doorkeeper::OAuth::Helpers
  describe JwtFlowHelper do
    describe '.retrieve_credentials' do
      let(:five_minutes_in_sec) { 5 * 60 }

      let(:application) do
        FactoryGirl.create(:application)
      end

      let(:encryption_method) { 'HS256' }

      let(:valid_jwt_hash) do
        {
            'iss' => application.uid,
            'aud' => 'http://www.thirdparty.com',
            'sub' => 'user@localsystem.com',
            'exp' => (Time.now + five_minutes_in_sec).to_i
        }
      end

      let(:expired_jwt_hash) do
        {
            'iss' => application.uid,
            'aud' => 'http://www.thirdparty.com',
            'sub' => 'user@localsystem.com',
            'exp' => (Time.now - five_minutes_in_sec).to_i
        }
      end

      let(:another_app_jwt_hash) do
        {
            'iss' => 'other_app_id',
            'aud' => 'http://www.thirdparty.com',
            'sub' => 'user@localsystem.com',
            'exp' => (Time.now + five_minutes_in_sec).to_i
        }
      end

      context 'when the assertion is signed with the same secret_key' do
        let(:assertion) do
          ::JWT.encode(valid_jwt_hash, application.secret, encryption_method)
        end

        it 'should return the client_id and client_secret' do
          client_id, client_secret = Doorkeeper::OAuth::Helpers::JwtFlowHelper.retrieve_credentials(assertion)

          expect(client_id).to eq(application.uid)
          expect(client_secret).to eq(application.secret)
        end
      end

      context 'when the assertion is signed with a different secret_key' do
        let(:assertion) do
          ::JWT.encode(valid_jwt_hash, 'other_secret', encryption_method)
        end

        it 'should return null for the client_id and client_secret when verify is set to true' do
          client_id, client_secret = Doorkeeper::OAuth::Helpers::JwtFlowHelper.retrieve_credentials(assertion)

          expect(client_id).to be_nil
          expect(client_secret).to be_nil
        end

        it 'should return the client_id and client_secret when verify is set to false' do
          client_id, client_secret = Doorkeeper::OAuth::Helpers::JwtFlowHelper.retrieve_credentials(assertion, false)

          expect(client_id).to eq(application.uid)
          expect(client_secret).to eq(application.secret)
        end
      end

      context 'when the assertion is exp has expired' do
        let(:assertion) do
          ::JWT.encode(expired_jwt_hash, 'other_secret', encryption_method)
        end

        it 'should return null for the client_id and client_secret when verify is set to true' do
          client_id, client_secret = Doorkeeper::OAuth::Helpers::JwtFlowHelper.retrieve_credentials(assertion)

          expect(client_id).to be_nil
          expect(client_secret).to be_nil
        end

        it 'should return the client_id and client_secret when verify is set to false' do
          client_id, client_secret = Doorkeeper::OAuth::Helpers::JwtFlowHelper.retrieve_credentials(assertion, false)

          expect(client_id).to eq(application.uid)
          expect(client_secret).to eq(application.secret)
        end
      end

      context 'when the iss can not be found' do
        let(:assertion) do
          ::JWT.encode(another_app_jwt_hash, application.secret, encryption_method)
        end

        it 'should return null for the client_id and client_secret' do
          client_id, client_secret = Doorkeeper::OAuth::Helpers::JwtFlowHelper.retrieve_credentials(assertion)

          expect(client_id).to be_nil
          expect(client_secret).to be_nil
        end
      end

      context 'when JWT.decode returns nil payload' do
        let(:assertion) do
          ::JWT.encode(another_app_jwt_hash, application.secret, encryption_method)
        end

        it 'should return null for the client_id and client_secret' do
          expected_decode_value = [nil, nil]
          allow(::JWT).to receive(:decode).with(assertion, nil, false, verify_expiration: false).and_return(expected_decode_value)
          client_id, client_secret = Doorkeeper::OAuth::Helpers::JwtFlowHelper.retrieve_credentials(assertion)

          expect(client_id).to be_nil
          expect(client_secret).to be_nil
        end
      end
    end
  end
end
