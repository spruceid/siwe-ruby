# frozen_string_literal: true

require "time"
require "eth"
require "json"

parsing_negative = JSON.parse(File.read("siwe/test/parsing_negative.json"))
parsing_positive = JSON.parse(File.read("siwe/test/parsing_positive.json"))
verification_negative = JSON.parse(File.read("siwe/test/verification_negative.json"))
verification_positive = JSON.parse(File.read("siwe/test/verification_positive.json"))

def days(num)
  num * 24 * 60 * 60
end

RSpec.describe Siwe::Message do
  before(:each) do
    @domain = "valid"
    @address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
    @uri = "https://example.com"
    @version = "1"
    @statement = "Example statement for SIWE"
    @issued_at = Time.now.utc.iso8601
    @nonce = Siwe::Util.generate_nonce
    @chain_id = 1
    @expiration_time = (Time.now.utc + days(2)).iso8601
    @not_before = (Time.now.utc + days(-1)).iso8601
    @request_id = "some-id"
    @resources = ["https://example.com/resources/1", "https://example.com/resources/2"]
    @message = Siwe::Message.new(@domain, @address, @uri, @version, {
                                   issued_at: @issued_at,
                                   statement: @statement,
                                   nonce: @nonce,
                                   chain_id: @chain_id,
                                   expiration_time: @expiration_time,
                                   not_before: @not_before,
                                   request_id: @request_id,
                                   resources: @resources
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
  end

  it "Creates a message with the correct fields using only mandatory ones" do
    @message = Siwe::Message.new(@domain, @address, @uri, @version)

    expect(@message.domain).to be @domain
    expect(@message.address).to eq(@address)
    expect(@message.uri).to be @uri
    expect(@message.version).to be @version
    expect(@message.issued_at).not_to eql("")
    expect(@message.nonce).not_to eql("")
    expect(@message.chain_id).to eql(1)
    expect(@message.expiration_time).to eql("")
    expect(@message.not_before).to eql("")
    expect(@message.request_id).to eql("")
    expect(@message.resources.length).to eql(0)
  end

  it "Returns a message for the object" do
    expect(@message.prepare_message.empty?)
  end

  it "Parses message to json string and json string to class" do
    json = @message.to_json_string
    expect(Siwe::Message.from_json_string(json) == @message)
  end

  it "Matches all fields of the created message when a string with all fields is given" do
    to_str = @message.prepare_message
    from_message = Siwe::Message.from_message(to_str)
    expect(from_message.prepare_message).to eql(to_str)
  end

  it "Matches all fields of the created message when a string with only mandarity fields" do
    m = Siwe::Message.new(@domain, @address, @uri, @version)

    to_str = m.prepare_message

    from_message = Siwe::Message.from_message(to_str)
    expect(from_message.prepare_message).to eql(to_str)
  end

  it "Matches all fields of the created message when a string with some optional fields" do
    @message = Siwe::Message.new(@domain, @address, @uri, @version, {
                                   issued_at: @issued_at,
                                   statement: @statement,
                                   nonce: @nonce,
                                   not_before: @not_before
                                 })

    to_str = @message.prepare_message
    from_message = Siwe::Message.from_message(to_str)
    expect(from_message.prepare_message).to eql(to_str)
  end

  it "Throws an error if the message is missing the signature" do
    expect { @message.verify("", nil, nil, nil) }.to raise_exception(Siwe::InvalidSignature, "Signature doesn't match message.")
  end

  it "Throws an error if the message is not yet valid" do
    key = Eth::Key.new
    @message.address = key.address.to_s
    @message.not_before = (Time.now.utc + days(1)).iso8601
    signature = key.personal_sign(@message.prepare_message)
    expect { @message.verify(signature, nil, nil, nil) }.to raise_exception(Siwe::NotValidMessage, "Message not yet valid.")
  end

  it "Throws an error if the message address is not EIP-55 complient" do
    key = Eth::Key.new
    @message.address = key.address.to_s.downcase
    signature = key.personal_sign(@message.prepare_message)
    expect do
      @message.verify(signature, nil, nil, nil)
    end.to raise_exception(Siwe::InvalidAddress,
                           "Address does not conform to EIP-55 or is invalid.")
  end

  it "Throws an error if the message is expired" do
    key = Eth::Key.new
    @message.address = key.address.to_s
    @message.not_before = Time.now.utc.iso8601
    @message.expiration_time = (Time.now.utc + days(-2)).iso8601
    signature = key.personal_sign(@message.prepare_message)
    expect { @message.verify(signature, nil, nil, nil) }.to raise_exception(Siwe::ExpiredMessage, "Expired message.")
  end

  it "Successfully verifys a signed message" do
    key = Eth::Key.new
    @message.address = key.address.to_s
    signature = key.personal_sign(@message.prepare_message)
    expect(@message.verify(signature, nil, nil, nil)).to eql(true)
  end

  parsing_positive.each do |t_name, value|
    it t_name do
      fields = value["fields"]
      parsed_message = Siwe::Message.from_message value["message"]
      expect(parsed_message.domain).to eql(fields["domain"])
      expect(parsed_message.address).to eql(fields["address"])
      expect(parsed_message.statement).to eql(fields["statement"])
      expect(parsed_message.uri).to eql(fields["uri"])
      expect(parsed_message.version).to eql(fields["version"])
      expect(parsed_message.chain_id).to eql(fields["chainId"])
      expect(parsed_message.nonce).to eql(fields["nonce"])
      expect(parsed_message.issued_at).to eql(fields["issuedAt"])
      expect(parsed_message.resources).to eql(fields["resources"])
      expect(parsed_message.not_before).to eql(fields["notBefore"])
      expect(parsed_message.expiration_time).to eql(fields["expirationTime"])
    end
  end

  parsing_negative.each do |t_name, value|
    it t_name do
      expect do
        Siwe::Message.from_message value
      end.to raise_exception(StandardError)
    end
  end

  verification_negative.each do |t_name, value|
    it t_name do
      expect do
        Siwe::Message.new(value["domain"], value["address"], value["uri"], value["version"], {
                            issued_at: value["issuedAt"],
                            statement: value["statement"],
                            nonce: value["nonce"],
                            chain_id: value["chainId"],
                            expiration_time: value["expirationTime"],
                            not_before: value["notBefore"],
                            request_id: value["requestId"],
                            resources: value["resource"]
                          }).verify(value["signature"], value["domainBinding"], value["time"], value["matchNonce"])
      end.to raise_exception(StandardError)
    end
  end

  verification_positive.each do |t_name, value|
    it t_name do
      expect(Siwe::Message.new(value["domain"], value["address"], value["uri"], value["version"], {
                                 issued_at: value["issuedAt"],
                                 statement: value["statement"],
                                 nonce: value["nonce"],
                                 chain_id: value["chainId"],
                                 expiration_time: value["expirationTime"],
                                 not_before: value["notBefore"],
                                 request_id: value["requestId"],
                                 resources: value["resource"]
                               }).verify(value["signature"], value["domainBinding"], value["time"], value["matchNonce"])).to eql(true)
    end
  end

  it "Fails with tempered message" do
    villain_key = Eth::Key.new
    key = Eth::Key.new
    @message.address = key.address.to_s
    signature = key.personal_sign(@message.prepare_message)
    @message.address = villain_key.address.to_s
    expect do
      @message.verify(signature, nil, nil, nil)
    end.to raise_exception(Siwe::InvalidSignature, "Signature doesn't match message.")
  end
end
