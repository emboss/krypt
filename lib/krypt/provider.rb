require_relative 'provider/provider'

begin
  require_relative 'provider/ffi'
rescue LoadError => e
  # cf. https://github.com/krypt/krypt/issues/47
  warn "krypt FFI provider could not be loaded. Error: #{e}"
end
