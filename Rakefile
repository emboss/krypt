require 'rake'
require 'rake/testtask'
require 'rspec/core/rake_task'

# require 'rubygems/package_task'
# require 'bundler'
# Bundler::GemHelper.install_tasks

def java?
  !! (RUBY_PLATFORM =~ /java/)
end

task :default => :test

Rake::TestTask.new('test') do |test|
  test.libs << 'lib'
  test.verbose = true
  test.test_files = Dir.glob('test/test_*.rb')
end

RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.ruby_opts = ['--1.9'] if java? 
  spec.fail_on_error = false
end

