module Doorkeeper
  module OAuth
    module Helpers
      module JwtFlow
        ERROR_VERIFICATION = 'There was an issue verifying the signature. Please verify the proper values.'
        ERROR_EXPIRED = 'The token has expired. Please regenerate a new one.'
        ERORR_UNEXPECTED = 'An error has occurred while trying to decode the message'

        def self.decode(assertion, secret, verify=true)
          payload = nil
          header = nil
          error = ''

          begin
            payload, header = ::JWT.decode(assertion, secret, verify)
          rescue ::JWT::VerificationError
            error = ERROR_VERIFICATION
          rescue ::JWT::ExpiredSignature
            error = ERROR_EXPIRED
          rescue ::JWT::DecodeError => e
            error =  "An error has occurred while trying to decode the message: #{e}"
          end

          [payload, header, error]
        end

        def self.retrieve_credentials(assertion, verify=true)
          payload, header = ::JWT.decode(assertion, nil, false, verify_expiration: false)
          uid = nil
          secret = nil

          if !payload
            return uid, secret
          end

          application = Doorkeeper::Application.by_uid(payload["iss"])

          if !application
            return uid, secret
          end

          uid = application.uid
          secret = application.secret

          if verify
            begin
              ::JWT.decode(assertion, application.secret)
            rescue ::JWT::DecodeError
              uid = nil
              secret = nil
            end
          end

           [uid, secret]
        end
      end
    end
  end
end