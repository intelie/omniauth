require 'omniauth/enterprise'
require 'ldap'

module OmniAuth
  module Strategies
    class JLDAP < LDAP
      include OmniAuth::Strategy

      # Initialize the LDAP Middleware
      #
      # @param [Rack Application] app Standard Rack middleware argument.
      # @option options [String, 'LDAP Authentication'] :title A title for the authentication form.
      def initialize(app, options = {}, &block)
        @app = app
        @name = options[:name] || :jldap
        @options = options
        @base = options.base
        @uid = options.uid || "uid"
        @host = options.host
        @port = options.port
        @bind_dn = options.bind_dn
        @password = options.password
        @name_proc = (@options.delete(:name_proc) || Proc.new {|name| name})

        yield self if block_given?
      end

      def connect
        if @options[:method] == :ssl
          java.lang.System::setProperty("javax.net.ssl.trustStore", @options[:store]) if @options[:store]
          conn = ::LDAP::SSLConn.new(host=@host, port=@port)
        else
          conn = ::LDAP::Conn.new(host=@host, port=@port)
        end
        conn
      end

      def bind(username, password)
        conn = connect

        #bind with an admin dn/password
        result = nil
        conn.bind(@bind_dn, @password) do

          #search for user
          conn.search(@base, ::LDAP::LDAP_SCOPE_SUBTREE,
                      "(#{@uid}=#{username})")  do |entry|
            result = entry
            break
          end          
        end
        
        if result
          @user_info = self.class.map_user(@@config, result)
          @user_info['uid'] = result[@uid.to_s].try(:first) || result['dn'].try(:first) || result['distinguishedName'].try(:first) || 
            @ldap_user_info = result
        else
          @user_info = nil
          @ldap_user_info = nil
        end

        result
      end
      
      protected
      

      def callback_phase
        creds = session['omniauth.ldap']
        session.delete 'omniauth.ldap'
        
        begin
          username = @name_proc.call(creds['username'])
          result = bind(username, creds['password'])
          
          if result
            @env['omniauth.auth'] = auth_hash
            call_app!
          else 
            fail!(:invalid_credentials)
          end

        rescue Exception => e
          puts "Erro authenticating with #{creds['username']} with #{@options.inspect}"
          puts e.inspect
          puts e.backtrace
          fail!(:invalid_credentials, e)
        end        
      end


      def self.map_user(mapper, object)
        user = {}
        mapper.each do |key, value|
          case value
          when String
            user[key] = object[value.to_s.downcase].first.to_s if object[value.to_s.downcase]
          when Array
            value.each {|v| (user[key] = object[v.to_s.downcase].first.to_s; break;) if object[v.to_s.downcase]}
          when Hash
            value.map do |key1, value1|
              pattern = key1.dup
              value1.each_with_index do |v,i|
                part = '';
                v.each {|v1| (part = object[v1.to_s.downcase].first.to_s; break;) if object[v1.to_s.downcase]}
                pattern.gsub!("%#{i}",part||'')
              end
              user[key] = pattern
            end
          end
        end
        user
      end

    end
  end
end
