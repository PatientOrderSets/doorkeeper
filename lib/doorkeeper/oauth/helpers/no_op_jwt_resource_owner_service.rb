module Doorkeeper
  module OAuth
   module Helpers
     class NoOpJwtResourceOwnerService
       def self.retrieve(payload)
         logger.warn(I18n.translate('doorkeeper.errors.messages.jwt_flow_not_configured'))
       end
     end
   end
  end
end
