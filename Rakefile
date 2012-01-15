require 'rake'
require 'rake/testtask'
require 'rspec/core/rake_task'

# require 'rubygems/package_task'
# require 'bundler'
# Bundler::GemHelper.install_tasks

task :default => :test

Rake::TestTask.new('test') do |test|
  test.libs << 'lib'
  test.verbose = true
  test.test_files = Dir.glob('test/test_*.rb')
end

RSpec::Core::RakeTask.new(:spec)
