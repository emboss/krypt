module Krypt
  
  # Abstract class that represents filters that can be combined with ordinary
  # IO instances, filtering the output before reading/writing to the underlying
  # IO. IOFilter instances can be stacked on top of each other, forming a 
  # "filter chain" that "peels of" multiple layers of encoding for example. 
  #
  # IOFilter supports a basic IO interface that responds to IO#read, IO#write
  # and IO#close.
  #
  # When reading from the IOFilter, the data will first be read from the IO,
  # processed according to the rules of the filter and only then passed on.
  #
  # When writing to the IOFilter, the data will first be processed by
  # applying the filter and only then written to the IO instance.
  #
  # Closing the IOFilter with IOFilter#close guarantees (among possibly
  # additional things) a call to IO#close on the underlying IO.
  class IOFilter
    
    #
    # call-seq: 
    #    IOFilter.new(io) -> IOFilter
    #
    # Constructs a new IOFilter with +io+ as its underlying IO. 
    #
    def initialize(io)
      @io = io
    end

    #
    # call-seq:
    #    io.close -> nil
    #
    # Calls, among possibly additional cleanup, IO#close on the underlying
    # IO.
    def close
      @io.close
    end
  end

  module BaseCodec

    def generic_read(len, read_len)
      data = @io.read(read_len)
      data = yield data if data
      if @buf
        data = data || ""
        data = @buf << data
      end
      return data unless len && data
      dlen = data.size
      remainder = dlen - len
      update_buffer(data, dlen, remainder)
      data
    end

    def generic_write(data, blk_size)
      return 0 unless data
      @write = true
      data = @buf ? @buf << data : data.dup
      dlen = data.size
      remainder = dlen % blk_size
      update_buffer(data, dlen, remainder)
      @io.write(yield data) if data.size > 0
    end

    def update_buffer(data, dlen, remainder)
      if remainder > 0
        @buf = data.slice!(dlen - remainder, remainder)
      else
        @buf = nil
      end
    end
  end

end

require_relative 'codec/hex'
require_relative 'codec/base64'

