# frozen_string_literal: true

require "time"
require "eth"
require "json"

DOMAIN = %r{(?<domain>[^/?#]+)}.freeze
SIWE_DOMAIN = %r{^#{DOMAIN.source} wants you to sign in with your Ethereum account:}.freeze

SIWE_ADDRESS = %r{\n(?<address>0x[a-zA-Z0-9]{40})\n\n}.freeze
SIWE_STATEMENT = %r{((?<statement>[^\n]+)\n)?}.freeze
RFC3986 = %r{(([^:?#]+):)?(([^?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?}.freeze
SIWE_URI_LINE = %r{\nURI: (?<uri>#{RFC3986.source}?)}.freeze
SIWE_VERSION = %r{\nVersion: (?<version>1)}.freeze
SIWE_CHAIN_ID = %r{\nChain ID: (?<chain_id>[0-9]+)}.freeze
SIWE_NONCE = %r{\nNonce: (?<nonce>[a-zA-Z0-9]{8,})}.freeze
SIWE_DATETIME = %r{([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))}.freeze
SIWE_ISSUED_AT = %r{\nIssued At: (?<issued_at>#{SIWE_DATETIME.source})}.freeze
SIWE_EXPIRATION_TIME = %r{(\nExpiration Time: (?<expiration_time>#{SIWE_DATETIME.source}))?}.freeze
SIWE_NOT_BEFORE = %r{(\nNot Before: (?<not_before>#{SIWE_DATETIME.source}))?}.freeze
SIWE_REQUEST_ID = %r{(\nRequest ID: (?<request_id>[-._~!$&'()*+,;=:@%a-zA-Z0-9]*))?}.freeze
SIWE_RESOURCES = %r{(\nResources:(?<resources>(\n- #{RFC3986.source}?)+))?$}.freeze

SIWE_MESSAGE = Regexp.new(SIWE_DOMAIN.source + SIWE_ADDRESS.source + SIWE_STATEMENT.source + SIWE_URI_LINE.source +
                          SIWE_VERSION.source + SIWE_CHAIN_ID.source + SIWE_NONCE.source + SIWE_ISSUED_AT.source +
                          SIWE_EXPIRATION_TIME.source + SIWE_NOT_BEFORE.source + SIWE_REQUEST_ID.source +
                          SIWE_RESOURCES.source)

puts SIWE_MESSAGE.source
module Siwe
  # Class that defines the EIP-4361 message fields and some utility methods to
  # generate/validate the messages
  class Message
    # RFC 4501 dns authority that is requesting the signing.
    attr_accessor :domain

    # Ethereum address performing the signing conformant to capitalization
    # encoded checksum specified in EIP-55 where applicable.
    attr_accessor :address

    # RFC 3986 URI referring to the resource that is the subject of the signing
    # (as in the __subject__ of a claim).
    attr_accessor :uri

    # Current version of the message.
    attr_accessor :version

    # EIP-155 Chain ID to which the session is bound, and the network where
    # Contract Accounts must be resolved.
    attr_accessor :chain_id

    # Randomized token used to prevent replay attacks, at least 8 alphanumeric
    # characters.
    attr_accessor :nonce

    # ISO 8601 datetime string of the current time.
    attr_accessor :issued_at

    # Human-readable ASCII assertion that the user will sign, and it must not
    # contain `\n`.
    attr_accessor :statement

    # ISO 8601 datetime string that, if present, indicates when the signed
    # authentication message is no longer valid.
    attr_accessor :expiration_time

    # ISO 8601 datetime string that, if present, indicates when the signed
    # authentication message will become valid.
    attr_accessor :not_before

    # System-specific identifier that may be used to uniquely refer to the
    # sign-in request.
    attr_accessor :request_id

    # List of information or references to information the user wishes to have
    # resolved as part of authentication by the relying party. They are
    # expressed as RFC 3986 URIs separated by `\n- `.
    attr_accessor :resources

    def initialize(domain, address, uri, version, options = {})
      @domain = domain
      @address = address
      @uri = uri
      @version = version
      @statement = options.fetch :statement, ""
      @issued_at = options.fetch :issued_at, Time.now.utc.iso8601
      @nonce = options.fetch :nonce, Siwe::Util.generate_nonce
      @chain_id = options.fetch :chain_id, 1
      @expiration_time = options.fetch :expiration_time, ""
      @not_before = options.fetch :not_before, ""
      @request_id = options.fetch :request_id, ""
      @resources = options.fetch :resources, []
      validate
    end

    def self.from_message(msg)
      message = msg.match SIWE_MESSAGE

      raise Siwe::UnableToParseMessage unless message.to_s == msg

      new(
        message[:domain],
        message[:address],
        message[:uri],
        message[:version],
        {
          statement: message[:statement],
          issued_at: message[:issued_at],
          nonce: message[:nonce],
          chain_id: message[:chain_id].to_i,
          expiration_time: message[:expiration_time],
          not_before: message[:not_before],
          request_id: message[:request_id],
          resources: message[:resources]&.split("\n- ")&.drop(1)
        }
      )
    end

    def to_json_string
      obj = {
        domain: @domain,
        address: Eth::Address.new(@address).to_s,
        uri: @uri,
        version: @version,
        chain_id: @chain_id,
        nonce: @nonce,
        issued_at: @issued_at,
        statement: @statement,
        expiration_time: @expiration_time,
        not_before: @not_before,
        request_id: @request_id,
        resources: @resources
      }
      obj.to_json
    end

    def self.from_json_string(str)
      obj = JSON.parse str, { symbolize_names: true }
      Siwe::Message.new(
        obj[:domain],
        obj[:address],
        obj[:uri],
        obj[:version], {
          chain_id: obj[:chain_id],
          nonce: obj[:nonce],
          issued_at: obj[:issued_at],
          statement: obj[:statement],
          expiration_time: obj[:expiration_time],
          not_before: obj[:not_before],
          request_id: obj[:request_id],
          resources: obj[:resources]
        }
      )
    end

    def validate
      # check domain
      raise Siwe::InvalidDomain unless @domain.match %r{[^/?#]*} || @domain.empty?

      # check address EIP-55
      raise Siwe::InvalidAddress unless Eth::Address.new(@address).to_s.eql? @address

      # check uri
      raise Siwe::InvalidURI unless URI.parse(@uri)

      # check version
      raise Siwe::InvalidMessageVersion unless @version == "1"

      # check if the nonce is alphanumeric and bigger then 8 characters
      raise Siwe::InvalidNonce unless @nonce.match(%r{[a-zA-Z0-9]{8,}})

      # check issued_at format
      begin
        Time.iso8601(@issued_at)
      rescue ArgumentError
        raise Siwe::InvalidTimeFormat, "issued_at"
      end

      # check exp_time
      begin
        Time.iso8601(@expiration_time) unless @expiration_time.nil? || @expiration_time.empty?
      rescue ArgumentError
        raise Siwe::InvalidTimeFormat, "expiration_time"
      end

      # check not_before
      begin
        Time.iso8601(@not_before) unless @not_before.nil? || @not_before.empty?
      rescue ArgumentError
        raise Siwe::InvalidTimeFormat, "not_before"
      end

      # check resources
      raise Siwe::InvalidURI unless @resources.nil? || @resources.empty? || @resources.each { |uri| URI.parse(uri) }
    end

    def verify(signature, domain, time, nonce)
      raise Siwe::DomainMismatch unless domain.nil? || domain.eql?(@domain)

      raise Siwe::NonceMismatch unless nonce.nil? || nonce.eql?(@nonce)

      check_time = time.nil? ? Time.now.utc : Time.iso8601(time)

      raise Siwe::ExpiredMessage if (!@expiration_time.nil? && !@expiration_time.empty?) && check_time > Time.iso8601(@expiration_time)

      raise Siwe::NotValidMessage if (!@not_before.nil? && !@not_before.empty?) && check_time < Time.iso8601(@not_before)

      raise Siwe::InvalidSignature if signature.nil? && signature.empty?

      raise Siwe::InvalidAddress unless @address.eql?(Eth::Address.new(@address).to_s)

      begin
        pub_key = Eth::Signature.personal_recover prepare_message, signature
        signature_address = Eth::Util.public_key_to_address pub_key
      rescue StandardError
        raise Siwe::InvalidSignature
      end

      raise Siwe::InvalidSignature unless signature_address.to_s.downcase.eql? @address.to_s.downcase

      true
    end

    def prepare_message
      greeting = "#{@domain} wants you to sign in with your Ethereum account:"
      address = @address
      statement = "\n#{@statement}\n"

      header = [greeting, address]

      if @statement.nil? || @statement.empty?
        header.push "\n"
      else
        header.push statement
      end

      header = header.join "\n"

      uri = "URI: #{@uri}"
      version = "Version: #{@version}"
      chain_id = "Chain ID: #{@chain_id}"
      nonce = "Nonce: #{@nonce}"
      issued_at = "Issued At: #{@issued_at}"

      body = [uri, version, chain_id, nonce, issued_at]

      expiration_time = "Expiration Time: #{@expiration_time}"
      not_before = "Not Before: #{@not_before}"
      request_id = "Request ID: #{@request_id}"

      body.push expiration_time unless @expiration_time.to_s.strip.empty?

      body.push not_before unless @not_before.to_s.strip.empty?

      body.push request_id unless @request_id.to_s.strip.empty?

      body.push "Resources:\n#{@resources.map { |x| "- #{x}" }.join "\n"}" unless @resources.nil? || @resources.empty?

      body = body.join "\n"

      [header, body].join "\n"
    end
  end
end
