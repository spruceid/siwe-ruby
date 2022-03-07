# frozen_string_literal: true

require_relative "siwe/version"

# Main module of siwe
module Siwe
  autoload :Message, "siwe/message"
  autoload :Util, "siwe/util"
  autoload :ExpiredMessage, "siwe/exceptions"
  autoload :NotValidMessage, "siwe/exceptions"
  autoload :InvalidSignature, "siwe/exceptions"
  autoload :InvalidAddress, "siwe/exceptions"

  class Error < StandardError; end
end
