# siwe-ruby
A Ruby implementation of EIP-4631: Sign In With Ethereum.

## Getting started
### Dependencies
Additional packages may be required to install the gem:

### macOS
```bash
brew install automake openssl libtool pkg-config gmp libffi
```

### Linux
```bash
sudo apt-get install build-essential automake pkg-config libtool \
                     libffi-dev libssl-dev libgmp-dev python-dev
```

After installing any required dependencies SIWE can be easily installed with:
```bash
gem install siwe
```

## Usage
SIWE provides a Message class which implements EIP-4361.
### Creating a SIWE Message

```ruby
require 'siwe'
require 'time'

# Only the mandatory arguments
Siwe::Message.new("domain.example", "0x9D85ca56217D2bb651b00f15e694EB7E713637D4", "some.uri", "1")

# Complete SIWE message with default values
Siwe::Message.new("domain.example", "0x9D85ca56217D2bb651b00f15e694EB7E713637D4", "some.uri", "1", {
                                   issued_at: Time.now.utc.iso8601,
                                   statement: "Example statement for SIWE",
                                   nonce: Siwe::Util.generate_nonce,
                                   chain_id: "1",
                                   expiration_time: "",
                                   not_before: "",
                                   request_id: "",
                                   resources: []
                                 })
```

### Parsing a SIWE Message
To parse from EIP-4361 use `Siwe::Message.from_message`

```ruby
require 'siwe'

Siwe::Message.from_message "domain.example wants you to sign in with your Ethereum account:\n0x9D85ca56217D2bb651b00f15e694EB7E713637D4\n\nExample statement for SIWE\n\nURI: some.uri\nVersion: 1\nChain ID: 1\nNonce: k1Ne4KWzBHYEFQo8\nIssued At: 2022-02-03T20:06:19Z"
```

Messages can be parsed to and from JSON strings, using Siwe::Message.from_json_string and Siwe::Message.to_json_string respectively:

```ruby
require 'siwe'

Siwe::Message.from_json_string "{\"domain\":\"domain.example\",\"address\":\"0x9D85ca56217D2bb651b00f15e694EB7E713637D4\",\"uri\":\"some.uri\",\"version\":\"1\",\"chain_id\":\"1\",\"nonce\":\"k1Ne4KWzBHYEFQo8\",\"issued_at\":\"2022-02-03T20:06:19Z\",\"statement\":\"Example statement for SIWE\",\"expiration_time\":\"\",\"not_before\":\"\",\"request_id\":\"\",\"resources\":[]}"

Siwe::Message.new("domain.example", "0x9D85ca56217D2bb651b00f15e694EB7E713637D4", "some.uri", "1").to_json_string
```

## Verifying and Authenticating a SIWE Message
Verification and authentication is performed via EIP-191, using the address field of the SiweMessage as the expected signer. The validate method checks message structural integrity, signature address validity, and time-based validity attributes.

```ruby
begin
    message.validate(signature) # returns true if valid throws otherwise
rescue Siwe::ExpiredMessage
    # Used when the message is already expired. (Expires At < Time.now)
rescue Siwe::NotValidMessage
    # Used when the message is not yet valid. (Not Before > Time.now)
rescue Siwe::InvalidSignature
    # Used when the signature doesn't correspond to the address of the message.
end
```

## Serialization of a SIWE Message
SiweMessage instances can also be serialized as their EIP-4361 string representations via the Siwe::Message.prepare_message method:

```ruby
require 'siwe'

Siwe::Message.new("domain.example", "0x9D85ca56217D2bb651b00f15e694EB7E713637D4", "some.uri", "1").prepare_message
Example
Parsing and verifying a Siwe::Message:
require 'siwe'

begin
    message = Siwe::Message.from_message "domain.example wants you to sign in with your Ethereum account:\n0x9D85ca56217D2bb651b00f15e694EB7E713637D4\n\nExample statement for SIWE\n\nURI: some.uri\nVersion: 1\nChain ID: 1\nNonce: k1Ne4KWzBHYEFQo8\nIssued At: 2022-02-03T20:06:19Z"
    message.validate("Some signature")
rescue Siwe::ExpiredMessage
    # Used when the message is already expired. (Expires At < Time.now)
rescue Siwe::NotValidMessage
    # Used when the message is not yet valid. (Not Before > Time.now)
rescue Siwe::InvalidSignature
    # Used when the signature doesn't correspond to the address of the message.
end
# Message has been validated. Authentication complete. Continue with authorization/other.
```