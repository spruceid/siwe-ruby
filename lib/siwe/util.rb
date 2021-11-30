require "securerandom"

module Siwe
  module Util
    extend self

    def generate_nonce
      SecureRandom.alphanumeric(16)
    end
  end
end
