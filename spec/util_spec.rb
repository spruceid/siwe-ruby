# frozen_string_literal: true

RSpec.describe Siwe::Util do
  it "Generates a random alphanumeric nonce" do
    expect(Siwe::Util.generate_nonce.match(/\A[a-zA-Z0-9]*\z/).nil?)
  end
end
