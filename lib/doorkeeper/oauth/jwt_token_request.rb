module Doorkeeper
  module OAuth
    class JwtTokenRequest
      include Validations
      include OAuth::RequestConcern
      include OAuth::Helpers

      validate :client,         error: :invalid_client
      validate :jwt,            error: :invalid_jwt
      validate :resource_owner, error: :invalid_grant
      validate :scopes,         error: :invalid_scope

      attr_accessor :server, :credentials, :access_token, :resource_owner, :assertion, :client

      def initialize(server, credentials, parameters = {})
        @server          = server
        @credentials     = credentials
        @original_scopes = parameters[:scope]
        @assertion = parameters[:assertion]

        if credentials
          @client = Application.by_uid credentials.uid
          @resource_owner  = retrieve_resource_owner
        end
      end

      private

      def retrieve_resource_owner
        payload = ::Doorkeeper::OAuth::Helpers::JwtFlow.decode(assertion, @client.secret)[0]

        return nil unless payload

        server.resource_owner_from_jwt.constantize.retrieve(payload)
      end

      def before_successful_response
        find_or_create_access_token(client, resource_owner.id, scopes, server)
      end

      def validate_jwt
        !!::Doorkeeper::OAuth::Helpers::JwtFlow.decode(assertion, @client.secret)[0]
      end

      def validate_resource_owner
        !!resource_owner
      end

      def validate_scopes
        return true unless @original_scopes.present?
        ScopeChecker.valid? @original_scopes, server.scopes, client.try(:scopes)
      end

      def validate_client
        !credentials || !!client
      end
    end
  end
end