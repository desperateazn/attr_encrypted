require 'encryptor'

# Adds attr_accessors that encrypt and decrypt an object's attributes
module AttrEncrypted
  autoload :Version, 'attr_encrypted/version'

  def self.extended(base) # :nodoc:
    base.class_eval do
      include InstanceMethods
      attr_writer :attr_encrypted_options
      @attr_encrypted_options, @encrypted_attributes = {}, {}
    end
  end

  # Generates attr_accessors that encrypt and decrypt attributes transparently
  #
  # Options (any other options you specify are passed to the encryptor's encrypt and decrypt methods)
  #
  #   :attribute        => The name of the referenced encrypted attribute. For example
  #                        <tt>attr_accessor :email, :attribute => :ee</tt> would generate an
  #                        attribute named 'ee' to store the encrypted email. This is useful when defining
  #                        one attribute to encrypt at a time or when the :prefix and :suffix options
  #                        aren't enough. Defaults to nil.
  #
  #   :prefix           => A prefix used to generate the name of the referenced encrypted attributes.
  #                        For example <tt>attr_accessor :email, :password, :prefix => 'crypted_'</tt> would
  #                        generate attributes named 'crypted_email' and 'crypted_password' to store the
  #                        encrypted email and password. Defaults to 'encrypted_'.
  #
  #   :suffix           => A suffix used to generate the name of the referenced encrypted attributes.
  #                        For example <tt>attr_accessor :email, :password, :prefix => '', :suffix => '_encrypted'</tt>
  #                        would generate attributes named 'email_encrypted' and 'password_encrypted' to store the
  #                        encrypted email. Defaults to ''.
  #
  #   :key              => The encryption key. This option may not be required if you're using a custom encryptor. If you pass
  #                        a symbol representing an instance method then the :key option will be replaced with the result of the
  #                        method before being passed to the encryptor. Objects that respond to :call are evaluated as well (including procs).
  #                        Any other key types will be passed directly to the encryptor.
  #
  #   :encode           => If set to true, attributes will be encoded as well as encrypted. This is useful if you're
  #                        planning on storing the encrypted attributes in a database. The default encoding is 'm' (base64),
  #                        however this can be overwritten by setting the :encode option to some other encoding string instead of
  #                        just 'true'. See http://www.ruby-doc.org/core/classes/Array.html#M002245 for more encoding directives.
  #                        Defaults to false unless you're using it with ActiveRecord, DataMapper, or Sequel.
  #
  #   :default_encoding => Defaults to 'm' (base64).
  #
  #   :marshal          => If set to true, attributes will be marshaled as well as encrypted. This is useful if you're planning
  #                        on encrypting something other than a string. Defaults to false unless you're using it with ActiveRecord
  #                        or DataMapper.
  #
  #   :marshaler        => The object to use for marshaling. Defaults to Marshal.
  #
  #   :dump_method      => The dump method name to call on the <tt>:marshaler</tt> object to. Defaults to 'dump'.
  #
  #   :load_method      => The load method name to call on the <tt>:marshaler</tt> object. Defaults to 'load'.
  #
  #   :encryptor        => The object to use for encrypting. Defaults to Encryptor.
  #
  #   :encrypt_method   => The encrypt method name to call on the <tt>:encryptor</tt> object. Defaults to 'encrypt'.
  #
  #   :decrypt_method   => The decrypt method name to call on the <tt>:encryptor</tt> object. Defaults to 'decrypt'.
  #
  #   :if               => Attributes are only encrypted if this option evaluates to true. If you pass a symbol representing an instance
  #                        method then the result of the method will be evaluated. Any objects that respond to <tt>:call</tt> are evaluated as well.
  #                        Defaults to true.
  #
  #   :unless           => Attributes are only encrypted if this option evaluates to false. If you pass a symbol representing an instance
  #                        method then the result of the method will be evaluated. Any objects that respond to <tt>:call</tt> are evaluated as well.
  #                        Defaults to false.
  #
  # You can specify your own default options
  #
  #   class User
  #     # now all attributes will be encoded and marshaled by default
  #     attr_encrypted_options.merge!(:encode => true, :marshal => true, :some_other_option => true)
  #     attr_encrypted :configuration, :key => 'my secret key'
  #   end
  #
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email, :credit_card, :key => 'some secret key'
  #     attr_encrypted :configuration, :key => 'some other secret key', :marshal => true
  #   end
  #
  #   @user = User.new
  #   @user.encrypted_email # nil
  #   @user.email? # false
  #   @user.email = 'test@example.com'
  #   @user.email? # true
  #   @user.encrypted_email # returns the encrypted version of 'test@example.com'
  #
  #   @user.configuration = { :time_zone => 'UTC' }
  #   @user.encrypted_configuration # returns the encrypted version of configuration
  #
  #   See README for more examples
  def attr_encrypted(*attributes)
    options = {
      :prefix           => 'encrypted_',
      :suffix           => '',
    }.merge!(attr_encrypted_options).merge!(attributes.last.is_a?(Hash) ? attributes.pop : {})

    attributes.each do |attribute|
      encrypted_attribute_name = (options[:attribute] ? options[:attribute] : [options[:prefix], attribute, options[:suffix]].join).to_sym

      instance_methods_as_symbols = instance_methods.collect { |method| method.to_sym }
      attr_reader encrypted_attribute_name unless instance_methods_as_symbols.include?(encrypted_attribute_name)
      attr_writer encrypted_attribute_name unless instance_methods_as_symbols.include?(:"#{encrypted_attribute_name}=")

      define_method(attribute) do
        instance_variable_get("@#{attribute}") || instance_variable_set("@#{attribute}", decrypt(attribute, send(encrypted_attribute_name)))
      end

      define_method("#{attribute}=") do |value|
        send("#{encrypted_attribute_name}=", encrypt(attribute, value))
        instance_variable_set("@#{attribute}", value)
      end

      define_method("#{attribute}?") do
        value = send(attribute)
        value.respond_to?(:empty?) ? !value.empty? : !!value
      end

      encrypted_attributes[attribute.to_sym] = options.merge(:attribute => encrypted_attribute_name)
    end
  end
  alias_method :attr_encryptor, :attr_encrypted

  # Default options to use with calls to <tt>attr_encrypted</tt>
  #
  # It will inherit existing options from its superclass
  def attr_encrypted_options
    @attr_encrypted_options ||= superclass.attr_encrypted_options.dup
  end

  # Checks if an attribute is configured with <tt>attr_encrypted</tt>
  #
  # Example
  #
  #   class User
  #     attr_accessor :name
  #     attr_encrypted :email
  #   end
  #
  #   User.attr_encrypted?(:name)  # false
  #   User.attr_encrypted?(:email) # true
  def attr_encrypted?(attribute)
    encrypted_attributes.has_key?(attribute.to_sym)
  end

  # Decrypts a value for the attribute specified
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email
  #   end
  #
  #   email = User.decrypt(:email, 'SOME_ENCRYPTED_EMAIL_STRING')
  def decrypt(attribute, encrypted_value, options = {})
    options = encrypted_attributes[attribute.to_sym].merge(options)
    if !encrypted_value.nil? && !(encrypted_value.is_a?(String) && encrypted_value.empty?) 
	  ciphertext = encrypted_value
  
      cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
      cipher.decrypt
  
      cipher_data = Base64.decode64(ciphertext)
  
      salt = cipher_data[0 .. 7]
      iv = cipher_data[8 .. 23]
      enc_data = cipher_data[24 .. -1]  # the rest
     
      key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(options[:key], salt, 1024, 32)
     
      cipher.key = key
      cipher.iv = iv
  
      plaintext = cipher.update(enc_data)
      plaintext << cipher.final
  
      plaintext
    else
      encrypted_value
    end
  end

  # Encrypts a value for the attribute specified
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email
  #   end
  #
  #   encrypted_email = User.encrypt(:email, 'test@example.com')
  def encrypt(attribute, value, options = {})
    options = encrypted_attributes[attribute.to_sym].merge(options)
    if !value.nil? && !(value.is_a?(String) && value.empty?)
	  plaintext = value.to_s

      cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
      cipher.encrypt
  
      iv = cipher.random_iv
      salt = (0 ... 8).map{65.+(rand(25)).chr}.join   # random salt
      key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(options[:key], salt, 1024, 32)

     
      cipher.key = key
      cipher.iv = iv
  
      enc_data = cipher.update(plaintext)
      enc_data << cipher.final
  
      final_data = salt << iv << enc_data
      encrypted_value = Base64.strict_encode64(final_data)
	 
	  encrypted_value
    else
      value
    end
  end

  # Contains a hash of encrypted attributes with virtual attribute names as keys
  # and their corresponding options as values
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email, :key => 'my secret key'
  #   end
  #
  #   User.encrypted_attributes # { :email => { :attribute => 'encrypted_email', :key => 'my secret key' } }
  def encrypted_attributes
    @encrypted_attributes ||= superclass.encrypted_attributes.dup
  end

  # Forwards calls to :encrypt_#{attribute} or :decrypt_#{attribute} to the corresponding encrypt or decrypt method
  # if attribute was configured with attr_encrypted
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email, :key => 'my secret key'
  #   end
  #
  #   User.encrypt_email('SOME_ENCRYPTED_EMAIL_STRING')
  def method_missing(method, *arguments, &block)
    if method.to_s =~ /^((en|de)crypt)_(.+)$/ && attr_encrypted?($3)
      send($1, $3, *arguments)
    else
      super
    end
  end

  module InstanceMethods
    # Decrypts a value for the attribute specified using options evaluated in the current object's scope
    #
    # Example
    #
    #  class User
    #    attr_accessor :secret_key
    #    attr_encrypted :email, :key => :secret_key
    #
    #    def initialize(secret_key)
    #      self.secret_key = secret_key
    #    end
    #  end
    #
    #  @user = User.new('some-secret-key')
    #  @user.decrypt(:email, 'SOME_ENCRYPTED_EMAIL_STRING')
    def decrypt(attribute, encrypted_value)
      self.class.decrypt(attribute, encrypted_value, evaluated_attr_encrypted_options_for(attribute))
    end

    # Encrypts a value for the attribute specified using options evaluated in the current object's scope
    #
    # Example
    #
    #  class User
    #    attr_accessor :secret_key
    #    attr_encrypted :email, :key => :secret_key
    #
    #    def initialize(secret_key)
    #      self.secret_key = secret_key
    #    end
    #  end
    #
    #  @user = User.new('some-secret-key')
    #  @user.encrypt(:email, 'test@example.com')
    def encrypt(attribute, value)
      self.class.encrypt(attribute, value, evaluated_attr_encrypted_options_for(attribute))
    end

    protected

      # Returns attr_encrypted options evaluated in the current object's scope for the attribute specified
      def evaluated_attr_encrypted_options_for(attribute)
        self.class.encrypted_attributes[attribute.to_sym].inject({}) { |hash, (option, value)| hash.merge!(option => evaluate_attr_encrypted_option(value)) }
      end

      # Evaluates symbol (method reference) or proc (responds to call) options
      #
      # If the option is not a symbol or proc then the original option is returned
      def evaluate_attr_encrypted_option(option)
        if option.is_a?(Symbol) && respond_to?(option)
          send(option)
        elsif option.respond_to?(:call)
          option.call(self)
        else
          option
        end
      end
  end
end

Object.extend AttrEncrypted

Dir[File.join(File.dirname(__FILE__), 'attr_encrypted', 'adapters', '*.rb')].each { |adapter| require adapter }
