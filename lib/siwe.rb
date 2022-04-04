# frozen_string_literal: true

require_relative "siwe/version"

# Main module of siwe
module Siwe
  autoload :Message, "siwe/message"
  autoload :Util, "siwe/util"
  autoload :ExpiredMessage, "siwe/exceptions"
  autoload :InvalidDomain, "siwe/exceptions"
  autoload :DomainMismatch, "siwe/exceptions"
  autoload :NonceMismatch, "siwe/exceptions"
  autoload :InvalidAddress, "siwe/exceptions"
  autoload :InvalidURI, "siwe/exceptions"
  autoload :InvalidNonce, "siwe/exceptions"
  autoload :NotValidMessage, "siwe/exceptions"
  autoload :InvalidTimeFormat, "siwe/exceptions"
  autoload :InvalidMessageVersion, "siwe/exceptions"
  autoload :InvalidSignature, "siwe/exceptions"
  autoload :UnableToParseMessage, "siwe/exceptions"

  class Error < StandardError; end
end
