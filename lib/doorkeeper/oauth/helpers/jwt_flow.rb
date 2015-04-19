module Doorkeeper
  module OAuth
    module Helpers
      module JwtFlow
        ERROR_VERIFICATION = 'There was an issue verifying the signature. Please verify the proper values.'
        ERROR_EXPIRED = 'The token has expired. Please regenerate a new one.'

        def self.decode(assertion, secret, verify=true)
          begin
            payload, header = ::JWT.decode(assertion, secret, verify)
            return payload, header, ''
          rescue ::JWT::VerificationError
            return nil, nil, ERROR_VERIFICATION
          rescue ::JWT::ExpiredSignature
            return nil, nil, ERROR_EXPIRED
          rescue ::JWT::DecodeError => e
            return nil, nil, "An error has occurred while trying to decode the message: #{e}"
          end
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
            rescue ::JWT::ExpiredSignature
              return nil, nil
            end
          end

          return uid, secret
        end
      end
    end
  end
end