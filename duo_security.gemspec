# -*- encoding: utf-8 -*-
require File.expand_path('../lib/duo_security/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Marten Veldthuis"]
  gem.email         = ["marten@veldthuis.com"]
  gem.description   = %q{Perform 2-factor authentication using duosecurity.com}
  gem.summary       = %q{}
  gem.homepage      = "https://github.com/roqua/duo_security"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "duo_security"
  gem.require_paths = ["lib"]
  gem.version       = DuoSecurity::VERSION

  gem.add_dependency "httparty", "~> 0.10"

  gem.add_development_dependency "minitest"
  gem.add_development_dependency "rake"
  gem.add_development_dependency "vcr", "~> 2.4.0"
  gem.add_development_dependency "webmock", "~> 1.8.9"
end
