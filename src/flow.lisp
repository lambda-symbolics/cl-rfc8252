(in-package #:cl-rfc8252)

;;;; -- Authorization and Token Exchange --

(defun browser-authentication-authorization-url (client &key redirect-uri state code-challenge)
  "Build an authorization URL with S256 PKCE and caller-owned provider extras."
  (format nil "~A~A~A" (client-authorization-endpoint client)
          (if (position #\? (client-authorization-endpoint client)) "&" "?")
          (quri:url-encode-params
           (append (list (cons "response_type" "code")
                         (cons "client_id" (client-id client))
                         (cons "redirect_uri" redirect-uri)
                         (cons "scope" (client-scope client))
                         (cons "state" state)
                         (cons "code_challenge" code-challenge)
                         (cons "code_challenge_method" "S256"))
                   (client-authorization-parameters client)))))

(defun browser-authentication-request (&key url content headers (request-wrapper #'funcall))
  "POST an OAuth form under the caller's response-deadline thunk wrapper.
Return body, HTTP status, and headers using cl-rfc8628's shared transport."
  (funcall request-wrapper
           (lambda ()
             (device-authentication-request
              :method ':post :url url
              :headers (append headers
                               (unless (assoc "Content-Type" headers :test #'string-equal)
                                 '(("Content-Type" . "application/x-www-form-urlencoded")))
                               (unless (assoc "Accept" headers :test #'string-equal)
                                 '(("Accept" . "application/json"))))
              :content content))))

(defun browser-authentication-token-document (client &key (endpoint (client-token-endpoint client))
                                                         parameters (stage ':token))
  "Request and validate a token JSON object without exposing credential material.
Redact request values and returned token fields before bounding error metadata."
  (funcall
   (client-secret-function client)
   (lambda ()
     (multiple-value-bind (body status)
         (handler-case
             (funcall
              (client-request-wrapper client)
              (lambda ()
                (if (client-request-function client)
                    (funcall (client-request-function client)
                             :url endpoint :content (quri:url-encode-params parameters))
                    (browser-authentication-request :url endpoint
                                                    :content (quri:url-encode-params parameters)
                                                    :headers (client-headers client)))))
           (error (condition)
             (if (typep condition (client-error-type client))
                 (error condition)
                 (browser-authentication--fail client stage "The OAuth token request failed."))))
       (let* ((document (handler-case (json-decode body) (error () nil)))
              (secrets (append (mapcar #'cdr parameters)
                               (loop for key in '("access_token" "refresh_token" "id_token" "client_secret" "code" "code_verifier")
                                     collect (json-get document key))))
              (error-value (json-get document "error")))
         (unless (and (integerp status) (<= 200 status 299)
                      (json-object-p document) (null error-value))
           (browser-authentication--fail
            client stage "The OAuth token endpoint rejected the request."
            :status (and (integerp status) status)
            :code (browser-authentication-redacted-value
                   client (if (stringp error-value) error-value (json-get error-value "code")) secrets)
            :response (browser-authentication-redacted-value
                     client (or (json-get document "error_description")
                                (json-get error-value "message")
                                (json-get error-value "description"))
                     secrets)))
         document)))))

(defun browser-authentication-exchange-code (client &key code verifier redirect-uri)
  "Exchange CODE using its original S256 VERIFIER and bound redirect URI."
  (browser-authentication-token-document
   client :stage ':token
   :parameters (append (list (cons "grant_type" "authorization_code")
                             (cons "client_id" (client-id client))
                             (cons "code" code)
                             (cons "code_verifier" verifier)
                             (cons "redirect_uri" redirect-uri))
                       (client-token-parameters client))))

;;;; -- Credential Publication --

(defun browser-authentication-login (client manager &key (stream *standard-output*)
                                                        (open-browser-p t)
                                                        (browser-function (client-browser-function client))
                                                        callback-function
                                                        (timeout (client-timeout client)))
  "Complete one installed-app login and publish provider-validated credentials.
CALLBACK-FUNCTION, when supplied, takes (listener state &key timeout) and owns
state validation. Always close the listener and scope the flow as secret use."
  (browser-authentication--validate-timeout client timeout)
  (funcall
   (client-secret-function client)
   (lambda ()
     (multiple-value-bind (verifier challenge)
         (browser-authentication-create-pkce :verifier-octets (client-verifier-octets client))
       (let ((state (funcall (client-state-function client))))
         (unless (non-empty-string-p state)
           (browser-authentication--fail client ':configuration "The OAuth state generator returned no state."))
         (multiple-value-bind (listener redirect-uri) (browser-authentication-loopback-open client)
           (unwind-protect
                (let ((url (browser-authentication-authorization-url
                            client :redirect-uri redirect-uri :state state :code-challenge challenge)))
                  (funcall (client-display-function client) url
                           :redirect-uri redirect-uri :timeout timeout :stream stream)
                  (when (and open-browser-p
                             (not (handler-case (funcall browser-function url) (error () nil))))
                    (funcall (client-browser-failure-function client) stream))
                  (finish-output stream)
                  (let* ((code (if callback-function
                                   (funcall callback-function listener state :timeout timeout)
                                   (browser-authentication-await-loopback
                                    client listener state :timeout timeout)))
                         (document (progn
                                     (browser-authentication-loopback-close listener)
                                     (setf listener nil)
                                     (browser-authentication-exchange-code
                                      client :code code :verifier verifier :redirect-uri redirect-uri)))
                         (credentials (funcall (client-credential-function client) manager document)))
                    (unless (typep credentials 'oauth-credentials)
                      (browser-authentication--fail client ':credentials
                                                    "The OAuth credential validator returned no credentials."))
                    (credential-manager-accept-account manager credentials :allow-change t)
                    (credential-source-save (credential-manager-primary-source manager) credentials)
                    credentials))
             (browser-authentication-loopback-close listener))))))))
