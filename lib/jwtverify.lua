--
-- JWT Validation implementation for HAProxy Lua host
--
-- Copyright (c) 2019. Adis Nezirovic <anezirovic@haproxy.com>
-- Copyright (c) 2019. Baptiste Assmann <bassmann@haproxy.com>
-- Copyright (c) 2019. Nick Ramirez <nramirez@haproxy.com>
-- Copyright (c) 2019. HAProxy Technologies LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Use HAProxy 'lua-load' to load optional configuration file which
-- should contain config table.
-- Default/fallback config
if not config then
  config = {
      debug = false,
      publicKey = nil,
      issuer = nil,
      audience = nil,
      hmacSecret = nil,
      queryString = nil,
      tokenExtract = nil
  }
end

local json   = require 'json'
local base64 = require 'base64'
local openssl = {
  pkey = require 'openssl.pkey',
  digest = require 'openssl.digest',
  x509 = require 'openssl.x509',
  hmac = require 'openssl.hmac'
}

local function log(msg)
  if config.debug then
      core.Debug(tostring(msg))
  end
end

local function dump(o)
  if type(o) == 'table' then
     local s = '{ '
     for k,v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ','
     end
     return s .. '} '
  else
     return tostring(o)
  end
end

function readAll(file)
  if file == nil then
      return nil
  end

  log("Reading file " .. file)
  local f = assert(io.open(file, "rb"))
  local content = f:read("*all")
  f:close()
  return content
end

local function validateAuthorizationHeader(authorizationHeader)
  local headerFields = core.tokenize(authorizationHeader, " .")

  if #headerFields ~= 4 then
      log("Improperly formated Authorization header. Should be 'Bearer' followed by 3 token sections.")
      return nil
  end

  if headerFields[1] ~= 'Bearer' then
      log("Improperly formated Authorization header. Missing 'Bearer' property.")
      return nil
  end

  return headerFields
end

local function validateQueryString(qs)
  local fields = core.tokenize(qs, ".")

  if #fields ~= 3 then
      log("Improperly formated query string parameter.")
      return nil
  end

  return fields
end

local function decodeJwt(header, payload, signature)
  local token = {}
  token.header = header
  token.headerdecoded = json.decode(base64.decode(token.header))

  token.payload = payload
  token.payloaddecoded = json.decode(base64.decode(token.payload))

  token.signature = signature
  token.signaturedecoded = base64.decode(token.signature)

  log('Decoded JWT header: ' .. dump(token.headerdecoded))
  log('Decoded JWT payload: ' .. dump(token.payloaddecoded))

  return token
end

local function extractJwt(txn)
  local authorizationHeader = txn.sf:req_hdr("Authorization")
  local headerFields = validateAuthorizationHeader(authorizationHeader)
  local queryStringKey = config.queryString

  if headerFields == nil and queryStringKey == nil then
      return nil
  end

  if headerFields == nil then
      local qs = txn.sf:urlp(queryStringKey)
      local headerFields = validateQueryString(qs)

      if headerFields == nil then
          return nil
      end
      return decodeJwt(headerFields[1], headerFields[2], headerFields[3])
  else
      return decodeJwt(headerFields[2], headerFields[3], headerFields[4])
  end
end

local function algorithmIsValid(token)
  if token.headerdecoded.alg == nil then
      log("No 'alg' provided in JWT header.")
      return false
  elseif token.headerdecoded.alg ~= 'HS256' and token.headerdecoded.alg ~= 'HS512' and token.headerdecoded.alg ~= 'RS256' then
      log("HS256, HS512 and RS256 supported. Incorrect alg in JWT: " .. token.headerdecoded.alg)
      return false
  end

  return true
end

local function rs256SignatureIsValid(token, publicKey)
  local digest = openssl.digest.new('SHA256')
  digest:update(token.header .. '.' .. token.payload)
  local vkey = openssl.pkey.new(publicKey)
  local isVerified = vkey:verify(token.signaturedecoded, digest)
  return isVerified
end

local function hs256SignatureIsValid(token, secret)
  local hmac = openssl.hmac.new(secret, 'SHA256')
  local checksum = hmac:final(token.header .. '.' .. token.payload)
  return checksum == token.signaturedecoded
end

local function hs512SignatureIsValid(token, secret)
  local hmac = openssl.hmac.new(secret, 'SHA512')
  local checksum = hmac:final(token.header .. '.' .. token.payload)
  return checksum == token.signaturedecoded
end

local function expirationIsValid(token)
  return os.difftime(token.payloaddecoded.exp, core.now().sec) > 0
end

local function issuerIsValid(token, expectedIssuer)
  return token.payloaddecoded.iss == expectedIssuer
end

local function audienceIsValid(token, expectedAudience)
  return token.payloaddecoded.aud == expectedAudience
end

local function tokenExtraction(txn, conf, token)
  if conf ~= nil then
      for i,value in ipairs(conf)
      do
          local tokenValue = token[value[2]]
          if type(tokenValue) == 'table' then
              tokenValue = table.concat(tokenValue, ';')
          end
          txn.http.req_set_header(txn.http, value[1], tostring(tokenValue))
      end
  end
end

function jwtverify(txn)
  local pem = config.publicKey
  local issuer = config.issuer
  local audience = config.audience
  local hmacSecret = config.hmacSecret
  local tokenExtract = config.tokenExtract

  -- 1. Decode and parse the JWT
  local token = extractJwt(txn)

  if token == nil then
    log("Token could not be decoded.")
    goto out
  end

  -- 2. Verify the signature algorithm is supported (HS256, HS512, RS256)
  if algorithmIsValid(token) == false then
      log("Algorithm not valid.")
      goto out
  end

  -- 3. Verify the signature with the certificate
  if token.headerdecoded.alg == 'RS256' then
    if publicKey == nil then
      log("Signature not valid.")
      goto out
    end
    if rs256SignatureIsValid(token, pem) == false then
      log("Signature not valid.")
      goto out
    end
  elseif token.headerdecoded.alg == 'HS256' then
    if hmacSecret == nil then
      log("Signature not valid.")
      goto out
    end
    if hs256SignatureIsValid(token, hmacSecret) == false then
      log("Signature not valid.")
      goto out
    end
  elseif token.headerdecoded.alg == 'HS512' then
    if hs512SignatureIsValid(token, hmacSecret) == false then
      log("Signature not valid.")
      goto out
    end
  end

  -- 4. Verify that the token is not expired
  if expirationIsValid(token) == false then
    log("Token is expired.")
    goto out
  end

  -- 5. Verify the issuer
  if issuer ~= nil and issuerIsValid(token, issuer) == false then
    log("Issuer not valid.")
    goto out
  end

  -- 6. Verify the audience
  if audience ~= nil and audienceIsValid(token, audience) == false then
    log("Audience not valid.")
    goto out
  end

  -- 7. Add scopes to variable
  if token.payloaddecoded.scope ~= nil then
    txn.set_var(txn, "txn.oauth_scopes", token.payloaddecoded.scope)
  else
    txn.set_var(txn, "txn.oauth_scopes", "")
  end

  -- 8. Set authorized variable
  log("req.authorized = true")
  txn.set_var(txn, "txn.authorized", true)

  tokenExtraction(txn, tokenExtract, token.payloaddecoded)

  -- exit
  do return end

  -- way out. Display a message when running in debug mode
::out::
 log("req.authorized = false")
 txn.set_var(txn, "txn.authorized", false)
end

-- Called after the configuration is parsed.
-- Loads the OAuth public key for validating the JWT signature.
core.register_init(function()
config.issuer = os.getenv("OAUTH_ISSUER")
config.audience = os.getenv("OAUTH_AUDIENCE")

-- when using an RS256 signature
local publicKeyPath = os.getenv("OAUTH_PUBKEY_PATH")
local pem = readAll(publicKeyPath)
config.publicKey = pem

-- when using an HS256 or HS512 signature
config.hmacSecret = os.getenv("OAUTH_HMAC_SECRET")
config.queryString = os.getenv("OAUTH_QUERY_STRING")

local tokenExtractHeaders = core.tokenize(os.getenv("OAUTH_EXTRACT_FORWARD_HEADERS") or "", " ")
local tokenExtractKeys = core.tokenize(os.getenv("OAUTH_EXTRACT_TOKEN_KEYS") or "", " ")
if #tokenExtractHeaders > 1 and #tokenExtractHeaders == #tokenExtractKeys then
    config.tokenExtract = {}
    for i,header in ipairs(tokenExtractHeaders)
    do
        table.insert(config.tokenExtract, {header, tokenExtractKeys[i]})
    end
    log("Token extraction will be performed"..dump(config.tokenExtract))
end

log("PublicKeyPath: " .. (publicKeyPath or "<none>"))
log("Issuer: " .. (config.issuer or "<none>"))
log("Audience: " .. (config.audience or "<none>"))
end)

-- Called on a request.
core.register_action('jwtverify', {'http-req'}, jwtverify, 0)
