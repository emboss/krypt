begin
  require 'simplecov'
  SimpleCov.start
rescue LoadError
end
require 'krypt'
require 'test/unit'
require_relative 'resources'
