# frozen_string_literal: true

require_relative "lib/siwe/version"

Gem::Specification.new do |spec|
  spec.name    = "siwe"
  spec.version = Siwe::VERSION
  spec.author  = "Spruce Systems Inc."
  spec.email   = ["hello@spruceid.com"]

  spec.summary     = "Sign-In with Ethereum"
  spec.description = "Sign-In with Ethereum library implementation"
  spec.homepage    = "https://login.xyz"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/spruceid/siwe-ruby"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.21"
  spec.metadata = {
    "rubygems_mfa_required" => "true"
  }
end
