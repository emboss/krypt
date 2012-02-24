require 'krypt-core'
require 'openssl'
require 'benchmark'

Benchmark.bm do |bm|

  n = 100000

  bm.report("Krypt::Digest empty string") do
    n.times do
      digest = Krypt::Digest::new("SHA1").digest("")
    end
  end

  bm.report("Krypt::Digest::SHA1 empty string") do
    n.times do
      digest = Krypt::Digest::SHA1.new.digest("")
    end
  end

  bm.report("OpenSSL::Digest empty string") do
    n.times do
      digest = OpenSSL::Digest.new("SHA1").digest("")
    end
  end

  n = 1_000_000

  bm.report("Krypt::Digest::SHA1 million times 'a'") do
    digest = Krypt::Digest::SHA1.new
    n.times do
      digest << "a"
    end
    s = digest.digest
  end

  bm.report("OpenSSL::Digest::SHA1 million times 'a'") do
    digest = OpenSSL::Digest::SHA1.new
    n.times do
      digest << "a"
    end
    s = digest.digest
  end

  n = 1000

  bm.report("Krypt::Digest::SHA1 million times 'a' at once") do
    n.times do
      digest = Krypt::Digest::SHA1.new
      digest << ("a" * 1_000_000)
      s = digest.digest
    end
  end

  bm.report("OpenSSL::Digest::SHA1 million times 'a' at once") do
    n.times do
      digest = OpenSSL::Digest::SHA1.new
      digest << ("a" * 1_000_000)
      s = digest.digest
    end
  end
end
