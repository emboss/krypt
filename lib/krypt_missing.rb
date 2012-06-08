unless Kernel.respond_to? :private_constant
  module Kernel
    def private_constant(*)
      # TODO delete when sufficiently supported
      nil
    end
  end
end


