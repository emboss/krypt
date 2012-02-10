source :rubygems

gem 'krypt-core',       :platforms => :ruby,  :path => File.expand_path('../krypt-core', File.dirname(__FILE__))
gem 'krypt-core-jruby', :platforms => :jruby, :path => File.expand_path('../krypt-core-jruby', File.dirname(__FILE__))

group :development do
  gem 'rake'
  gem 'rspec'
  gem 'jruby-openssl', :platforms => :jruby
end

group :test do
  gem 'simplecov', :require => false
end

gemspec
