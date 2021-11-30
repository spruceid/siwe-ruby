require "siwe"

m = Siwe::Message.new("gregorio.ninja", "0x1234567", "gregorio.ninja", "1")

puts m.personal_message
