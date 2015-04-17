module Doorkeeper
  module OAuth
    module Helpers
      module JwtFlowHelper
        def self.decode(assertion, verify=true)

        end

        def self.retrieve_credentials(assertion, verify=true)
          payload, header = ::JWT.decode(assertion, nil, false, verify_expiration: false)

          return nil, nil unless payload

          application = Doorkeeper::Application.find_by_uid(payload["iss"])

          return nil, nil unless application

          uid = application.uid
          secret = application.secret

          if verify
            begin
              ::JWT.decode(assertion, application.secret)
              return uid, secret
            rescue ::JWT::VerificationError
              return nil, nil
            end
          end

          return uid, secret
        end
      end
    end
  end
end