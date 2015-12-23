# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'
require 'json/ext'

class LogStash::Filters::Ipreputation < LogStash::Filters::Base

  config_name 'ipreputation'

  config :host, :validate => :string, :default => '127.0.0.1'
  config :port, :validate => :number, :default => 6379
  config :db, :validate => :number, :default => 0
  config :password, :validate => :password
  config :timeout, :validate => :number, :default => 5
  config :reconnect_interval, :validate => :number, :default => 1

  # The name used to specify which field of event has IP value
  config :ip_field_name, :validate => :string, :default => 'message'

  # If true, it will add a behaviour field to event for all behaviour
  # and add each reputation of behaviour to separated field
  config :separate_reputation, :validate => :boolean, :default => false


  public
  def register
    require 'redis'
    @redis = nil

    @reputation = 'reputation'
    @behaviour = 'behaviour'
  end # def register

  public
  def filter(event)
    begin
      if event[@ip_field_name]
        @logger.info('In filter event now')
        # Multiple IP like "192.168.0.1, 192.168.0.2", will take first one
        ip = event[@ip_field_name].split(',')[0]
        @redis ||= connect
        reputation = @redis.hgetall(ip)
        if @separate_reputation

          if reputation.empty?
            event[@behaviour] = ['unknown']
          else
            event[@behaviour] = reputation.keys
            reputation.each { |k, v|  event[k] = v.to_i}
          end

        else
          event[@reputation] = reputation.to_json
        end

        filter_matched(event)
      end
    rescue => e
      @logger.warn('Failed to get value from Redis', :event => event,
                    :exception => e,
                    :backtrace => e.backtrace)
      sleep @reconnect_interval
      @redis = nil
      retry
    end
  end # def filter

  private
  def connect
    params = {
        :host => @host,
        :port => @port,
        :db => @db,
        :password => @password.nil? ? nil : @password.value,
        :timeout => @timeout
    }
    @logger.debug(params)
    Redis.new(params)
  end # def connect

end # class LogStash::Filters::Ipreputation
