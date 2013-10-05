#!/usr/bin/ruby
#coding: utf-8
# Before running, set these environment variables:
# export SSL_CERT_FILE=/path_to/cacert.pem
# export SMTP_USER_NAME=username
# export SMTP_PASSWORD=password
require 'rubygems'
require 'bcrypt'
require 'sinatra'
require 'sinatra/flash'
require 'sinatra/reloader' if development?
require 'slim'; Slim::Engine.set_default_options :pretty => true
require 'data_mapper'
require 'json'
require 'sass'
require 'pony'
require 'omniauth-facebook'
require 'omniauth-twitter'
require 'colorize'
require 'encrypted_cookie'
use Rack::Session::EncryptedCookie, :secret => "fdstodsds0435m4kbvbtrkr545'02krfmmt0èu54cmjff83d2'ìel.4j9c"
use OmniAuth::Builder do
  provider :facebook, '290594154312564',       'a26bcf9d7e254db82566f31c9d72c94e'
  provider :twitter,  'cO23zABqRXQpkmAXa8MRw', 'TwtroETQ6sEDWW8HEgt0CUWxTavwFcMgAwqHdb0k1M'
end

DataMapper::Logger.new(STDOUT, :debug)
DataMapper::Property::String.length(255)
DataMapper.setup(:default, ENV['DATABASE_URL'] || "sqlite3://#{Dir.pwd}/development.db")
Pony.options = {
  :from    => 'Sinatra TESTing',
  :subject => 'Sinatra TESTing',
  :body    => 'Hello there.',
  :via     => :smtp,
  :via_options => {
    :address              => 'smtp.gmail.com',
    :port                 => '587',
    :enable_starttls_auto => true,
    :user_name            => ENV['SMTP_USER_NAME'],
    :password             => ENV['SMTP_PASSWORD'],
    :authentication       => :plain, # :plain, :login, :cram_md5, no auth by default
    :domain               => "localhost.localdomain" # the HELO domain provided by the client to the server
  }
}
class Session
  include DataMapper::Resource
  property :id,                       Serial
  property :auth_token,               String
  property :active,                   Boolean, :default => true
  property :agent,                    String
  property :ip,                       String
  property :started,                  String
  property :permanent,                Boolean
  property :created_at,               DateTime
  property :updated_at,               DateTime
  belongs_to :user
end

class Login
  include DataMapper::Resource
  property :id,                       Serial
  property :provider,                 String
  property :uid,                      String
  property :nickname,                 String
  property :email,                    String
  property :data,                     Text
  property :created_at,               DateTime
  property :updated_at,               DateTime
  belongs_to :user
end

class User
  include DataMapper::Resource
  property :id,                       Serial
  property :email,                    String
  property :username,                 String
  property :password_hash,            String
  property :password_salt,            String
  property :locale,                   String
  property :password_reset_token,     String 
  property :password_reset_sent_at,   DateTime
  property :email_confirmation_token, String
  property :email_confirmed,          Boolean,  :default => false
  property :created_at,               DateTime
  property :updated_at,               DateTime
  has n, :sessions
  has n, :logins
end
DataMapper.finalize
# DataMapper.auto_migrate! # To create a new database

configure do
    set :send_email, false
    set :permanent_cookies_days, 15
end

helpers do
  def cookie(cookie_name)
    return request.cookies[cookie_name]
  end
  def cookie_set(cookie_name, cookie_value, permanent = false)
    max_age = (60 * 60 * 24 * settings.permanent_cookies_days).to_s if permanent
    response.set_cookie cookie_name, {:value=> cookie_value, :max_age => max_age, :path => "/"}
  end
  def cookie_destroy(cookie_name)
    response.delete_cookie cookie_name
  end
  def logged_in?
    current_user ? true : false
  end
  def log_in(user, args = {})
    args[:permanent] ||= false
    args[:started]   ||= "password"
    token = generate_token
    cookie_set('token', token, args[:permanent])
    sess = user.sessions.create(:auth_token => token, :agent => request.user_agent, :ip => request.ip, :started => args[:started], :permanent => args[:permanent])
  end
  def log_out
    if current_session
      current_session.active = false
      current_session.save
    end
    cookie_destroy('token')
  end
  def current_session
    return @current_session if @current_session
    if cookie('token')
      if @current_session = Session.first(:auth_token => cookie('token'))
        return @current_session
      else
        cookie_destroy('token')
      end
    else
      return nil
    end
  end
  def current_user
    if @current_user
      logger.info "current_user: Answering cached user #{@current_user.id} Line:#{__LINE__}".yellow
      return @current_user if @current_user
    else
      if current_session
        @current_user = current_session.user
        logger.info "current_user: Answering user #{@current_user.id} Line:#{__LINE__}".yellow
        return @current_user
      else
        logger.info "current_user: Returning nil Line:#{__LINE__}".yellow
        return nil
      end
    end
  end
  def title_for_html
    return "Documentation" if request.path_info == "/"
    return request.path_info.match(/^\/([^\/]+)/)[1].gsub("_", " ").split(" ").map(&:capitalize).join(" ")
  end
  def link_to_unless_current(text, location)
    if request.path_info == location
      text
    else
      "<a href='#{location}'>#{text}</a>"
    end
  end
  def generate_token(length = 40)
    return (rand(36**length).to_s(36))
  end      
  def time_in_words(timestamp)
		minutes = ((DateTime.now - timestamp) * 24 * 60).to_i
    case minutes
      when 0..59            then "#{minutes} minutes ago"
      when 60..(60*24)      then "#{(minutes/60).floor} hours ago"
      else                       "#{(minutes/60*24).floor} days ago"
    end
  end
  def create_omniauth_login(user, provider, omniauth)  
    login = user.logins.create(
      :uid      => omniauth['uid'], 
      :provider => provider,
      :nickname => omniauth[:info][:nickname],
      :email    => omniauth[:info][:email],
      :data     => JSON.pretty_generate(omniauth)
    )
    user.username ||= omniauth[:info][:nickname]
    user.email    ||= omniauth[:info][:email]
    user.save
  end
end

get "/" do
  slim :home
end

get '/auth/:provider/callback' do
  omniauth = request.env['omniauth.auth']
  if omniauth['uid'].blank?
    flash[:errors] = "Error, no UID returned by #{params[:provider].capitalize}."
  else
    if logged_in?
      if login = Login.first(:uid => omniauth['uid'], :provider => params[:provider])
        # Provider Account already exist
        if login.user_id == current_user.id
          # Provider Account and Current User are THE SAME
          flash[:errors] = "Your account is already connected with this #{params[:provider].capitalize} account."
        else
          # Provider Account and Current User are NOT the same
          flash[:errors] = "Account #{omniauth[:info][:nickname]} di #{params[:provider].capitalize} already used to log in the system. Log out from this account before logging in with #{params[:provider].capitalize}."
        end
      else
        # Connecting Current User with the Provider
        create_omniauth_login(current_user, params[:provider], omniauth)
      end  
    else  
      if login = Login.first( :uid => omniauth['uid'], :provider => params[:provider] )
        # Provider Account already exist, need to log it in
        log_in(login.user, :started => params[:provider])
        flash[:messages] = "Logged in as #{omniauth[:info][:nickname]} using your #{params[:provider].capitalize} account."
      else
        # Provider Account is new, need to crete it, create the user and login
        create_omniauth_login(User.create, params[:provider], omniauth)
        log_in(user, :started => params[:provider])
        flash[:messages] = "Signed in as #{omniauth[:info][:nickname]} using your #{params[:provider].capitalize} account."
      end
    end
  end
  redirect "/"
end

get '/auth/failure' do
  flash[:errors] = "Failure: #{params.to_yaml}"
	redirect "/" 
end

get '/auth/:provider/deauthorized' do
  flash[:errors] = "#{params[:provider]} has deauthorized this app."
	redirect "/" 
end

get "/your_data" do
  if logged_in?
    slim :your_data
  else
    flash[:errors] = "You need to be logged in to see your data."
    redirect "/" 
  end
end

get "/sign_up" do
  @params = JSON.parse(flash[:params]) if flash[:params]
  slim :sign_up
end

get "/email_confirmation/:email/:email_confirmation_token" do
  if user = User.first(:email => params[:email], :email_confirmation_token => params[:email_confirmation_token], :email_confirmed => false)
    user.email_confirmed = true
    user.save!
    flash.now[:messages] = "Your email has been confirmed. Thanks."
  else
    flash.now[:errors] = "The confirmation code is wrong or it has been already used."
  end
  slim :home
end

post "/sign_up" do
  errors = []
  email = params[:email].strip.downcase
  errors.push "Email cannot be empty." if email.empty?
  errors.push "The email #{email} already exist in the system." if !email.empty? and User.first(:email => email)
  errors.push "Password cannot be less than 1 characters long." if params[:password].length < 1
  errors.push "The re-typed password doesn't match the password." if params[:password] != params[:checkpassword]
  if errors.empty?
    password_salt = BCrypt::Engine.generate_salt
    password_hash = BCrypt::Engine.hash_secret(params[:password], password_salt)
    user = User.new(
      :password_hash            => password_hash,
      :password_salt            => password_salt,
      :username                 => email,
      :email                    => email,
      :email_confirmation_token => generate_token()
    )
    url_to_confirm_email = "#{request.url}/email_confirmation/#{user.email}/#{user.email_confirmation_token}".gsub("/sign_up/", "/")
    if user.save
      if settings.send_email
        Pony.mail(
          :to => email,
          :subject => "Email confirmation",
          :body => "Go to #{url_to_confirm_email} for email confirmation."
        )
      end
      log_in(user, :permanent => ( params[:keep_me_logged_in] == "yes" ))
      flash[:messages] = "Signed up as #{email}. Check your email and follow the instruction to confirm your address."
      redirect "/"
    else
      user.errors.each do |error|
        errors.push error
      end
    end
  end
  flash[:errors] = errors.join(" ")
  flash[:params] = JSON.generate(params)
	redirect "/sign_up" 
end

get "/log_in" do
  @params = JSON.parse(flash[:params]) if flash[:params]
  slim :log_in
end

post "/log_in" do
  email = params[:email].strip.downcase
  if user = User.first(:email => email)
    if user.password_hash == BCrypt::Engine.hash_secret(params[:password], user.password_salt)
      log_in(user, :permanent => (params[:keep_me_logged_in] == "yes") )
      flash[:messages] = "Logged in as #{email}"
      redirect "/"
    end
  end
  flash[:errors] = "Wrong email or password, please try again."
  flash[:params] = JSON.generate(params)
  redirect "/log_in"
end

get "/data_dump" do
  if request.host == "localhost"
    slim :data_dump
  else
    redirect "/"
  end
end

get "/log_out" do
  log_out
  flash[:messages] = "You have been logged out."
  redirect "/"
end

get '/styles.css' do
  sass :styles
end

__END__

@@layout
doctype html
html
  head
    meta charset="utf-8"
    title Sinatra Authentication
    link rel="stylesheet" media="screen, projection" href="/styles.css"
    link rel="stylesheet" type="text/css" href="http://fonts.googleapis.com/css?family=Cabin"
    link href="http://fonts.googleapis.com/css?family=Allan:bold" rel="stylesheet" type="text/css"
  body
    - if flash[:errors]
      #errors class="top"== flash[:errors]
    - if flash[:messages]
      #messages class="top"== flash[:messages]
    #title class="top"
      h1 Authentication [from scratch] with Sinatra
      ul class="menu"
        li
          ==link_to_unless_current("Documentation", "/")
        - if logged_in?
          li
            ==link_to_unless_current("Your Data", "/your_data")
          li
            ==link_to_unless_current("Log Out", "/log_out")
          li
            a href='/auth/facebook' Add a Facebook account
          li
            a href='/auth/twitter' Add a Twitter account
          li Logged in as #{current_user.username}
        - else
          li
            ==link_to_unless_current("Log In", "/log_in")
          li
            ==link_to_unless_current("Sign Up", "/sign_up")
          li
            a href='/auth/facebook' Login with Facebook
          li
            a href='/auth/twitter' Login with Twitter
    .main_div
      h1 #{title_for_html}
      == yield
      - if request.host == "localhost"
        div style="margin-top:3em; text-align: center"
          ==link_to_unless_current("Data Dump", "/data_dump")

@@sign_up
.myform id="stylized"
  form action="/sign_up" method="post"
    div
      label for="email" Email:
      input#email type="text" name="email" value="#{@params["email"]}"
    div
      label for="password" Password:
      input#password type="password" name="password"
    div
      label for="checkpassword" Re-type Password:
      input#password type="password" name="checkpassword"
    div
      label for="keep_me_logged_in" Keep me logged in:
      input#forgot_your_password type="checkbox" name="keep_me_logged_in" value="yes"
    div style="margin-top: 2em"
      input type="submit" value="Sign Up"

@@log_in
.myform id="stylized"
  form action="/log_in" method="post"
    div
      label for="email" Email:
      input#email type="text" name="email" value="#{@params["email"]}"
    div
      label for="password" Password:
      input#password type="password" name="password"
      a href="/forgot_your_password" Forgot your password?
    div
      label for="keep_me_logged_in" Keep me logged in:
      input#forgot_your_password type="checkbox" name="keep_me_logged_in" value="yes"
    div style="margin-top: 2em"
      input type="submit" value="Log in"


@@your_data
h1 Logins
table border="1"
  tr
    th Provider
    th UID
    th Nickname
    th Email
    th Updated
  - current_user.logins.all.each do |record|
    tr
      td ==record.provider
      td ==record.uid
      td ==record.nickname
      td ==record.email
      td ==time_in_words(record.updated_at)
h1 Sessions
table border="1"
  tr
    th IP
    th Updated
    th Time
    th Started
    th Permanent
    th Active
  - current_user.sessions.all.reverse.each do |record|
    - if record.active and record.auth_token == cookie('token')
      - active = "Current"
    - else
      - active = record.active.to_s.capitalize
    tr class=active
      td ==record.ip          
      td ==record.updated_at
      td ==time_in_words(record.updated_at)
      td ==record.started
      td ==record.permanent
      td ==active
h1 Current User
pre
  = current_user.to_yaml
  
@@data_dump

h1 current_user
pre
  == current_user.to_yaml
h1 cookies
pre
  == request.cookies.to_yaml
h1 Users
- User.all.each do |record|
  pre #{record.to_yaml}
h1 Sessions
- Session.all.each do |record|
  pre #{record.to_yaml}
h1 Logins
- Login.all.each do |record|
  pre #{record.to_yaml}
h1 Environment
pre
  - env.keys.each do |key|
    == "#{key}: #{env[key]}\n"
h1 request
pre
  == "request.user_agent: #{request.user_agent}\n"
  == "request.ip: #{request.ip}\n"
  == "request.path: #{request.path}\n"
  == "request.url: #{request.url}\n"
  == "request.referrer: #{request.referrer}\n"
  == "request.host: #{request.host}\n"
  == "request.port: #{request.port}\n"
  == "request.path_info: #{request.path_info}\n"
  == "request.script_name: #{request.script_name}\n"
h1 request.to_yaml
pre
  == request.to_yaml

    
    
  
@@home
div 
  p This is an authorization test site that I built while learning about Sinatra. I did not tested it and I don't take any responsability about its relaiability. Use with care.
  p If you have any questions or suggestions about improvement please leave a comment.
  h2 Characteristics:
  ul
    li The normal sign Up procedure is based on email/password authentication. The email need to be unique in the database.
    li It is possible to login using other providers. I included Facebook and Twitter but it is simple to add any other, in Omniauth has the. For this I used the Omniauth library (<a href="http://www.omniauth.org/">www.omniauth.org</a>).
    li It sends a message for email confirmation. The user would need to click on the link that is sent to confirm the email. The smtp user name and password are stored in the environment variables. Execute these lines from shell before running the script.
    ul
      li export SMTP_USER_NAME = username
      li export SMTP_PASSWORD = password
    
    
	
@@styles
html, body, ul, ol, li, form, fieldset, legend 
  margin: 0
  padding: 0
h1, h2, h3, h4, h5, h6, p
  margin-top: 0
fieldset,img
  border: 0
legend
  color: #000
sup
  vertical-align: text-top
sub
  vertical-align: text-bottom
table
  border-collapse: collapse
  border-spacing: 0
caption, th, td
  text-align: left
  vertical-align: top
  font-weight: normal
input, textarea, select
  font-size: 110%
  line-height: 1.1
abbr, acronym
  border-bottom: .1em dotted
  cursor: help


ul, ol
  margin-left: 3em
body
  font-family: 'Cabin', Helvetica, Arial, sans-serif
h1
  font-family: 'Allan', Georgia, Times, serif
  margin-top: 1em
th
  text-align: center
  font-weight: bold
  background-color: #ccc
td
  padding: 2px
  padding-right: 8px
  padding-left: 8px

.Current
  background-color: #dfd
.False
  background-color: #fdd

.main_div
  padding: 5em
  padding-top: 2em

ul.menu
  margin: 0px
  li
    display: inline
    margin-right: 10px
    
.top
  padding: 10px
  width: 100%
  text-align: center
#title
  background: #fac
  text-align: left
  padding-left: 5em
#errors
  background: orange
#messages
  background: #9d9
#stylized
  label
    display: block
    text-align: right
    width: 140px
    float: left
