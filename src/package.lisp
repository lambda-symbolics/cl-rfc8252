(defpackage #:cl-rfc8252
  (:nicknames #:rfc8252)
  (:use #:cl)
  (:import-from #:cl-rfc8628
                #:credential-error #:credential-manager-accept-account
                #:credential-manager-primary-source #:credential-source-save
                #:oauth-credentials #:json-decode #:json-object-p #:json-get
                #:non-empty-string-p
                #:redact-exact-string-values #:safe-redaction-marker
                #:device-authentication-monotonic-seconds
                #:device-authentication-open-browser #:device-authentication-request)
  (:export #:browser-authentication-client
           #:browser-authentication-error #:browser-authentication-error-stage
           #:browser-authentication-error-status #:browser-authentication-error-code
           #:browser-authentication-error-response #:browser-authentication-fail
           #:browser-authentication-create-pkce #:browser-authentication-state
           #:browser-authentication-authorization-url
           #:browser-authentication-loopback-open #:browser-authentication-loopback-close
           #:browser-authentication-await-loopback
           #:browser-authentication-redacted-value #:browser-authentication-request
           #:browser-authentication-token-document #:browser-authentication-exchange-code
           #:browser-authentication-login))
