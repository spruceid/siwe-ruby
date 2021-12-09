# frozen_string_literal: true

require "time"
require "eth"

def days(num)
  num * 24 * 60 * 60
end

RSpec.describe Siwe::Message do
  before(:each) do
    @domain = "https://example.com"
    @address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
    @uri = "https://example.com"
    @version = "1"
    @statement = "Example statement for SIWE"
    @issued_at = Time.now.utc.iso8601
    @nonce = Siwe::Util.generate_nonce
    @chain_id = "1"
    @expiration_time = (Time.now.utc + days(2)).iso8601
    @not_before = (Time.now.utc + days(1)).iso8601
    @request_id = "some-id"
    @resources = ["https://example.com/resources/1", "https://example.com/resources/2"]
    @signature = "A signature"
    @message = Siwe::Message.new(@domain, @address, @uri, @version, {
                                   issued_at: @issued_at,
                                   statement: @statement,
                                   nonce: @nonce,
                                   chain_id: @chain_id,
                                   expiration_time: @expiration_time,
                                   not_before: @not_before,
                                   request_id: @request_id,
                                   resources: @resources,
                                   signature: @signature
                                 })
  end

  it "Creates a message with the correct fields with all fields" do
    expect(@message.domain).to eql(@domain)
    expect(@message.address).to eql(@address)
    expect(@message.uri).to eql(@uri)
    expect(@message.version).to eql(@version)
    expect(@message.issued_at).to eql(@issued_at)
    expect(@message.nonce).to eql(@nonce)
    expect(@message.chain_id).to eql(@chain_id)
    expect(@message.expiration_time).to eql(@expiration_time)
    expect(@message.not_before).to eql(@not_before)
    expect(@message.request_id).to eql(@request_id)
    expect(@message.resources).to eql(@resources)
    expect(@message.signature).to eql(@signature)
  end

  it "Creates a message with the correct fields using only mandatory ones" do
    @message = Siwe::Message.new(@domain, @address, @uri, @version)

    expect(@message.domain).to be @domain
    expect(@message.address).to be @address
    expect(@message.uri).to be @uri
    expect(@message.version).to be @version
    expect(@message.issued_at).not_to eql("")
    expect(@message.nonce).not_to eql("")
    expect(@message.chain_id).to eql("1")
    expect(@message.expiration_time).to eql("")
    expect(@message.not_before).to eql("")
    expect(@message.request_id).to eql("")
    expect(@message.resources.length).to eql(0)
    expect(@message.signature).to eql("")
  end

  it "Returns a message for the object" do
    expect(@message.personal_sign.empty?)
  end

  it "Parses message to json string and json string to class" do
    json = @message.to_json_string
    expect(Siwe::Message.from_json_string(json) == @message)
  end

  it "Matches all fields of the created message when a string with all fields is given" do
    to_str = @message.personal_sign
    from_message = Siwe::Message.from_message(to_str)
    expect(from_message.personal_sign).to eql(to_str)
  end

  it "Matches all fields of the created message when a string with only mandarity fields" do
    @message = Siwe::Message.new(@domain, @address, @uri, @version)

    to_str = @message.personal_sign
    from_message = Siwe::Message.from_message(to_str)
    expect(from_message.personal_sign).to eql(to_str)
  end

  it "Matches all fields of the created message when a string with some optional fields" do
    @message = Siwe::Message.new(@domain, @address, @uri, @version, {
                                   issued_at: @issued_at,
                                   statement: @statement,
                                   nonce: @nonce,
                                   not_before: @not_before
                                 })

    to_str = @message.personal_sign
    from_message = Siwe::Message.from_message(to_str)
    expect(from_message.personal_sign).to eql(to_str)
  end

  it "Throws an error if the message is missing the signature" do
    @message.signature = ""
    expect { @message.validate }.to raise_exception(RuntimeError, "Missing signature field.")
  end

  it "Successfully validates a signed message" do
    key = Eth::Key.new
    @message.address = key.address
    @message.signature = key.personal_sign(@message.personal_sign)
    expect @message.validate
  end

  it "Fails with tempered message" do
    villain_key = Eth::Key.new
    key = Eth::Key.new
    @message.address = key.address
    @message.signature = key.personal_sign(@message.personal_sign)
    @message.address = villain_key.address
    expect { @message.validate }.to raise_exception(RuntimeError, "Signature doesn't match message.")
  end
end
