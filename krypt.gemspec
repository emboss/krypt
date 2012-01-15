require 'fileutils'

Gem::Specification.new do |s|
  s.name = 'krypt'
  s.version = '0.0.1'
  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@googlemail.com'
  s.homepage = 'https://github.com/emboss/krypt'
  s.files = Dir.glob('{lib,lib,spec,test}/**/*') # TODO: add README, etc.
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.require_path = "lib"
end
