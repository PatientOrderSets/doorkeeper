require 'spec_helper'
require 'active_support/core_ext/string'
require 'doorkeeper/oauth/client'
require 'doorkeeper/oauth/helpers/jwt_flow_helper'
require 'jwt'

class Doorkeeper::OAuth::Client
  describe 'Methods' do
    let(:client_id) { 'some-uid' }
    let(:client_secret) { 'some-secret' }

    subject do
      Class.new do
        include Methods
      end.new
    end

    describe :from_params do
      it 'returns credentials from parameters when Authorization header is not available' do
        request     = double parameters: { client_id: client_id, client_secret: client_secret }
        uid, secret = subject.from_params(request)

        expect(uid).to    eq('some-uid')
        expect(secret).to eq('some-secret')
      end

      it 'is blank when there are no credentials' do
        request     = double parameters: {}
        uid, secret = subject.from_params(request)

        expect(uid).to    be_blank
        expect(secret).to be_blank
      end
    end

    describe :from_basic do
      let(:credentials) { Base64.encode64("#{client_id}:#{client_secret}") }

      it 'decodes the credentials' do
        request     = double authorization: "Basic #{credentials}"
        uid, secret = subject.from_basic(request)

        expect(uid).to    eq('some-uid')
        expect(secret).to eq('some-secret')
      end

      it 'is blank if Authorization is not Basic' do
        request     = double authorization: "#{credentials}"
        uid, secret = subject.from_basic(request)

        expect(uid).to    be_blank
        expect(secret).to be_blank
      end
    end

    describe :from_jwt do
      context 'when a valid jwt is returned from the JwtFlow helper' do
        let(:jwt_hash) do
          {'iss' => "#{client_id}",
           'aud' => 'http://www.thirdparty.com',
           'sub' => 'user@localsystem.com'}
        end

        let(:credentials) do
          ::JWT.encode(jwt_hash, client_secret, 'HS256')
        end

        it 'returns the credentials from the JWT' do
          expected_credentials = [client_id, client_secret]
          allow(Doorkeeper::OAuth::Helpers::JwtFlowHelper).to receive(:retrieve_credentials).with(credentials).and_return(expected_credentials)

          request     = double parameters: {assertion: "#{credentials}"}
          uid, secret = subject.from_jwt(request)

          expect(uid).to    eq(client_id)
          expect(secret).to eq(client_secret)
        end
      end

      context 'when nil is returned from the JwtFlow helper' do
        let(:jwt_hash) do
          {'iss' => "#{client_id}",
           'aud' => 'http://www.thirdparty.com',
           'sub' => 'user@localsystem.com'}
        end

        let(:credentials) do
          ::JWT.encode(jwt_hash, client_secret, 'HS256')
        end

        it 'returns the credentials that are blank' do
          expected_credentials = [nil, nil]
          allow(Doorkeeper::OAuth::Helpers::JwtFlowHelper).to receive(:retrieve_credentials).with(credentials).and_return(expected_credentials)

          request     = double parameters: {assertion: "#{credentials}"}
          uid, secret = subject.from_jwt(request)

          expect(uid).to    be_blank
          expect(secret).to be_blank
        end
      end
    end
  end
end
