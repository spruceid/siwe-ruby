require "time"

module Siwe
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

    # Signature of the message signed by the wallet.
    attr_accessor :signature

    def initialize(domain, address, uri, version, options = {})
      @domain = domain
      @address = address
      @uri = uri
      @version = version

      @issued_at = options.fetch(:issued_at, Time.now.utc.iso8601)
      @nonce = options.fetch(:nonce, Siwe::Util.generate_nonce)
      @chain_id = options.fetch(:chain_id, "1")
      @expiration_time = options.fetch(:expiration_time, "")
      @not_before = options.fetch(:not_before, "")
      @request_id = options.fetch(:request_id, "")
      @resources = options.fetch(:resources, [])
      @signature = options.fetch(:signature, "")
    end

    def personal_message
      greeting = "#{@domain} wants you to sign in with your Ethereum account:"
      address = @address.to_s

      header = [greeting, address].join("\n")

      uri = "URI: #{@uri}"
      version = "Version #{@version}"
      chain_id = "Chain ID: #{@chain_id}"
      nonce = "Nonce: #{@nonce}"
      issued_at = "Issued At: #{@issued_at}"

      body = [uri, version, chain_id, nonce, issued_at]

      expiration_time = "Expiration Time: #{@expiration_time}"
      not_before = "Not Before: #{@not_before}"
      request_id = "Request ID: #{@request_id}"
      resources = "Resources: #{@resources.each { |x| "- #{x}" }.join("\n")}"

      body.push(expiration_time) unless @expiration_time.to_s.strip.empty?

      body.push(not_before) unless @not_before.to_s.strip.empty?

      body.push(request_id) unless @request_id.to_s.strip.empty?

      body.push(resources) unless @resources.length == 0

      body = body.join("\n")

      [header, body].join("\n\n")
    end
  end
end
