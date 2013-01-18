module Krypt
  class HMAC
    include Krypt::Helper::XOR

    def initialize(digest, key)
      @digest = digest
      @key = process_key(key)

      # hash ipad
      @digest << xor("\x36" * @digest.block_length, @key)
    end

    def update(data)
      @digest << data
    end
    alias << update

    def digest
      inner_digest = @digest.digest
      # hash opad
      @digest << xor("\x5c" * @digest.block_length, @key)
      @digest << inner_digest
      @digest.digest
    end

    def hexdigest
      Krypt::Hex.encode(digest)
    end

    class << self

      def digest(md, key, data)
        hmac = self.new(md, key)
        hmac << data
        hmac.digest
      end

      def hexdigest(md, key, data)
        Krypt::Hex.encode(digest(md, key, data))
      end

    end

    private

      def process_key(key)
        key_size = key.size
        block_len = @digest.block_length

        if key_size < block_len
          key.dup.tap do |new_key|
            (block_len - key_size).times { new_key << 0 }
          end
        elsif key_size > block_len
          @digest.digest(key)
        else
          key
        end
      end

  end
end
