# frozen_string_literal: true

require "securerandom"

module Siwe
  # Utilities functions for the Siwe library
  module Util
    module_function

    def generate_nonce
      SecureRandom.alphanumeric(16)
    end
  end
end
