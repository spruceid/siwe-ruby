# frozen_string_literal: true

require "time"
require "eth"
require "json"

SIWE_DOMAIN = "^(?<domain>([^?#]*)) wants you to sign in with your Ethereum account:\\n"
SIWE_ADDRESS = "(?<address>0x[a-zA-Z0-9]{40})\\n\\n"
SIWE_STATEMENT = "((?<statement>[^\\n]+)\\n)?\\n"
SIWE_URI = "(([^:?#]+):)?(([^?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))"
SIWE_URI_LINE = "URI: (?<uri>#{SIWE_URI}?)\\n"
SIWE_VERSION = "Version: (?<version>1)\\n"
SIWE_CHAIN_ID = "Chain ID: (?<chain_id>[0-9]+)\\n"
SIWE_NONCE = "Nonce: (?<nonce>[a-zA-Z0-9]{8,})\\n"
SIWE_DATETIME = "([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9])"\
                ":([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))"
SIWE_ISSUED_AT = "Issued At: (?<issued_at>#{SIWE_DATETIME})"
SIWE_EXPIRATION_TIME = "(\\nExpiration Time: (?<expiration_time>#{SIWE_DATETIME}))?"
SIWE_NOT_BEFORE = "(\\nNot Before: (?<not_before>#{SIWE_DATETIME}))?"
SIWE_REQUEST_ID = "(\\nRequest ID: (?<request_id>[-._~!$&'()*+,;=:@%a-zA-Z0-9]*))?"
SIWE_RESOURCES = "(\\nResources:(?<resources>(\\n- #{SIWE_URI}?)+))?$"

SIWE_MESSAGE = "#{SIWE_DOMAIN}#{SIWE_ADDRESS}#{SIWE_STATEMENT}#{SIWE_URI_LINE}#{SIWE_VERSION}#{SIWE_CHAIN_ID}"\
               "#{SIWE_NONCE}#{SIWE_ISSUED_AT}#{SIWE_EXPIRATION_TIME}#{SIWE_NOT_BEFORE}#{SIWE_REQUEST_ID}"\
               "#{SIWE_RESOURCES}"

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
      begin
        @address = Eth::Address.new(address).to_s
      rescue StandardError
        raise Siwe::InvalidAddress
      end
      raise Siwe::InvalidAddress unless @address.eql? address

      @uri = uri
      @version = version
      @statement = options.fetch :statement, ""
      @issued_at = options.fetch :issued_at, Time.now.utc.iso8601
      @nonce = options.fetch :nonce, Siwe::Util.generate_nonce
      @chain_id = options.fetch :chain_id, "1"
      @expiration_time = options.fetch :expiration_time, ""
      @not_before = options.fetch :not_before, ""
      @request_id = options.fetch :request_id, ""
      @resources = options.fetch :resources, []
    end

    def self.from_message(msg)
      if (message = msg.match SIWE_MESSAGE)
        new(
          message[:domain],
          Eth::Address.new(message[:address]).to_s,
          message[:uri],
          message[:version],
          {
            statement: message[:statement] || "",
            issued_at: message[:issued_at],
            nonce: message[:nonce],
            chain_id: message[:chain_id],
            expiration_time: message[:expiration_time] || "",
            not_before: message[:not_before] || "",
            request_id: message[:request_id] || "",
            resources: message[:resources]&.split("\n- ")&.drop(1) || []
          }
        )

      else
        throw "Invalid message input."
      end
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

    def validate(signature)
      raise Siwe::ExpiredMessage if !@expiration_time.empty? && Time.now.utc > Time.parse(@expiration_time)
      raise Siwe::NotValidMessage if !@not_before.empty? && Time.now.utc < Time.parse(@not_before)

      raise Siwe::InvalidSignature if signature.empty?

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

      if @statement.empty?
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
      resources = "Resources:\n#{@resources.map { |x| "- #{x}" }.join "\n"}"

      body.push expiration_time unless @expiration_time.to_s.strip.empty?

      body.push not_before unless @not_before.to_s.strip.empty?

      body.push request_id unless @request_id.to_s.strip.empty?

      body.push resources unless @resources.empty?

      body = body.join "\n"

      [header, body].join "\n"
    end
  end
end
