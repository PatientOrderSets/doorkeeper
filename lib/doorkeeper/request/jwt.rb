module Doorkeeper
  module Request
    class Jwt
      GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'

      def self.build(server)
        new(server.credentials, server)
      end

      attr_accessor :credentials, :server

      def initialize(credentials, server)
        @credentials, @server = credentials, server
      end

      def request
        @request ||= OAuth::JwtTokenRequest.new(Doorkeeper.configuration, credentials, server.parameters)
      end

      def authorize
        request.authorize
      end
    end
  end
end