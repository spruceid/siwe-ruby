# frozen_string_literal: true

require "time"

def days(num)
  num * 24 * 60 * 60
end

RSpec.describe Siwe::Message do
  before(:each) do
    @domain = "https://example.com"
    @address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
    @uri = "https://example.com"
    @version = "1"
    @issued_at = Time.now.utc.iso8601
    @nonce = Siwe::Util.generate_nonce
    @chain_id = "1"
    @expiration_time = (Time.now.utc + days(2)).iso8601
    @not_before = (Time.now.utc + days(1))
    @request_id = "some-id"
    @resources = ["https://example.com/resources/1", "https://example.com/resources/2"]
    @signature = "A signature"
  end

  it "Creates a message with the correct fields with all fields" do
    message = Siwe::Message.new(@domain, @address, @uri, @version, {
                                  issued_at: @issued_at,
                                  nonce: @nonce,
                                  chain_id: @chain_id,
                                  expiration_time: @expiration_time,
                                  not_before: @not_before,
                                  request_id: @request_id,
                                  resources: @resources,
                                  signature: @signature
                                })

    expect(message.domain).to eql(@domain)
    expect(message.address).to eql(@address)
    expect(message.uri).to eql(@uri)
    expect(message.version).to eql(@version)
    expect(message.issued_at).to eql(@issued_at)
    expect(message.nonce).to eql(@nonce)
    expect(message.chain_id).to eql(@chain_id)
    expect(message.expiration_time).to eql(@expiration_time)
    expect(message.not_before).to eql(@not_before)
    expect(message.request_id).to eql(@request_id)
    expect(message.resources).to eql(@resources)
    expect(message.signature).to eql(@signature)
  end

  it "Creates a message with the correct fields using only mandatory ones" do
    message = Siwe::Message.new(@domain, @address, @uri, @version)

    expect(message.domain).to be @domain
    expect(message.address).to be @address
    expect(message.uri).to be @uri
    expect(message.version).to be @version
    expect(message.issued_at).not_to eql("")
    expect(message.nonce).not_to eql("")
    expect(message.chain_id).to eql("1")
    expect(message.expiration_time).to eql("")
    expect(message.not_before).to eql("")
    expect(message.request_id).to eql("")
    expect(message.resources.length).to eql(0)
    expect(message.signature).to eql("")
  end

  it "Returns a message for the object" do
    message = Siwe::Message.new(@domain, @address, @uri, @version, {
                                  issued_at: @issued_at,
                                  nonce: @nonce,
                                  chain_id: @chain_id,
                                  expiration_time: @expiration_time,
                                  not_before: @not_before,
                                  request_id: @request_id,
                                  resources: @resources,
                                  signature: @signature
                                })
    expect(message.personal_message.empty?)
  end
end
