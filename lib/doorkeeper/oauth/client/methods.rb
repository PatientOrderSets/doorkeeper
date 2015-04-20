module Doorkeeper
  module OAuth
    class Client
      module Methods
        def from_params(request)
          request.parameters.values_at(:client_id, :client_secret)
        end

        def from_basic(request)
          authorization = request.authorization
          if authorization.present? && authorization =~ /^Basic (.*)/m
            Base64.decode64($1).split(/:/, 2)
          end
        end

        def from_jwt(request)
          client_id, client_secret =
              Doorkeeper::OAuth::Helpers::JwtFlow.retrieve_credentials(request.parameters[:assertion])

          [client_id, client_secret]
        end
      end
    end
  end
end
