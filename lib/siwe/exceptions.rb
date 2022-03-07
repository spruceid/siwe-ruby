# frozen_string_literal: true

module Siwe
  # Used when the message is already expired. (Expires At < Time.now)
  class ExpiredMessage < StandardError
    def initialize(msg = "Message expired.")
      super
    end
  end

  # Used when the address does not conform to EIP-55 or is invalid.
  class InvalidAddress < StandardError
    def initialize(msg = "Address does not conform to EIP-55 or is invalid.")
      super
    end
  end

  # Used when the message is not yet valid. (Not Before > Time.now)
  class NotValidMessage < StandardError
    def initialize(msg = "Message not yet valid.")
      super
    end
  end

  # Used when the signature doesn't correspond to the address of the message.
  class InvalidSignature < StandardError
    def initialize(msg = "Signature doesn't match message.")
      super
    end
  end
end
