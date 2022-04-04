# frozen_string_literal: true

module Siwe
  # Used when the message is already expired. (Expires At < Time.now)
  class ExpiredMessage < StandardError
    def initialize(msg = "Expired message.")
      super
    end
  end

  # Used when the domain is not a valid authority or is empty.
  class InvalidDomain < StandardError
    def initialize(msg = "Invalid domain.")
      super
    end
  end

  # Used when the domain don't match the domain provided for verification.
  class DomainMismatch < StandardError
    def initialize(msg = "Domain do not match provided domain for verification.")
      super
    end
  end

  # Used when the nonce don't match the nonce provided for verification.
  class NonceMismatch < StandardError
    def initialize(msg = "Nonce do not match provided nonce for verification.")
      super
    end
  end

  # Used when the address does not conform to EIP-55 or is invalid.
  class InvalidAddress < StandardError
    def initialize(msg = "Address does not conform to EIP-55 or is invalid.")
      super
    end
  end

  # Used when the message is created with an invalid URI
  class InvalidURI < StandardError
    def initialize(msg = "URI does not conform to RFC 3986.")
      super
    end
  end

  # Used when the nonce is smaller then 8 characters or is not alphanumeric
  class InvalidNonce < StandardError
    def initialize(msg = "Nonce size smaller then 8 characters or is not alphanumeric.")
      super
    end
  end

  # Used when the message is not yet valid. (Not Before > Time.now)
  class NotValidMessage < StandardError
    def initialize(msg = "Message not yet valid.")
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
end
