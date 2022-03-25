# frozen_string_literal: true

module Siwe
  # Used when the message is already expired. (Expires At < Time.now)
  class ExpiredMessage < StandardError
    def initialize(msg = "Message expired.")
      super
    end
  end

  # Used when the domain is not a valid authority or is empty.
  class InvalidDomain < StandardError
    def initialize(msg = "Domain is not a valid authority or is empty.")
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

  # Used when the message doesn't match the RegExp.
  class UnableToParseMessage < StandardError
    def initialize(msg = "Unable to parse message.")
      super
    end
  end

  # Used when the message contain a time format not complient to ISO8601.
  class InvalidTimeFormat < StandardError
    def initialize(field, msg = "Invalid time format for: #{field}")
      super
    end
  end

  # Used when the message version is not 1.
  class InvalidMessageVersion < StandardError
    def initialize(msg = "Invalid message version.")
      super
    end
  end
end
