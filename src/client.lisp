(in-package #:cl-rfc8252)

;;;; -- Conditions and Caller Policy --

(define-condition browser-authentication-error (credential-error)
  ((stage :initarg :stage :reader browser-authentication-error-stage
          :documentation "The OAuth stage that failed.")
   (status :initarg :status :initform nil :reader browser-authentication-error-status
           :documentation "An optional HTTP response status.")
   (code :initarg :code :initform nil :reader browser-authentication-error-code
         :documentation "An optional redacted and bounded OAuth error code.")
   (response :initarg :response :initform nil :reader browser-authentication-error-response
             :documentation "An optional redacted and bounded error description."))
  (:documentation "A browser OAuth failure carrying no credential material."))

(defun browser-authentication-fail (&key stage message status code response)
  "Signal a structured browser OAuth failure with safe metadata."
  (error 'browser-authentication-error :stage stage :message message
         :status status :code code :response response))

(defclass browser-authentication-client ()
  ((authorization-endpoint :initarg :authorization-endpoint :reader client-authorization-endpoint
                           :documentation "The provider's authorization endpoint.")
   (token-endpoint :initarg :token-endpoint :reader client-token-endpoint
                   :documentation "The provider's token endpoint.")
   (client-id :initarg :client-id :reader client-id
              :documentation "The public installed-app client identifier.")
   (scope :initarg :scope :initform "" :reader client-scope
          :documentation "The space-separated requested scopes.")
   (authorization-parameters :initarg :authorization-parameters :initform nil
                             :reader client-authorization-parameters
                             :documentation "Provider-specific authorization query parameters.")
   (token-parameters :initarg :token-parameters :initform nil :reader client-token-parameters
                     :documentation "Provider-specific token form parameters, such as a client secret.")
   (ports :initarg :ports :initform '(0) :reader client-ports
          :documentation "Ordered loopback ports; a sole zero requests an ephemeral port.")
   (redirect-host :initarg :redirect-host :initform "127.0.0.1" :reader client-redirect-host
                  :documentation "The advertised IPv4 loopback host, 127.0.0.1 or localhost.")
   (callback-path :initarg :callback-path :initform "/callback" :reader client-callback-path
                  :documentation "The exact absolute path accepted for OAuth callbacks.")
   (verifier-octets :initarg :verifier-octets :initform 32 :reader client-verifier-octets
                    :documentation "The 32-96 random octets encoded into the PKCE verifier.")
   (state-function :initarg :state-function :initform #'browser-authentication-state
                   :reader client-state-function :documentation "A fresh, unpredictable state generator.")
   (state-test :initarg :state-test :initform #'equal :reader client-state-test
               :documentation "The caller's predicate of received and expected state strings.")
   (timeout :initarg :timeout :initform 900 :reader client-timeout
            :documentation "The overall browser callback timeout in seconds.")
   (request-timeout :initarg :request-timeout :initform 5 :reader client-request-timeout
                    :documentation "The maximum seconds spent reading one local request line.")
   (line-limit :initarg :line-limit :initform 8192 :reader client-line-limit
               :documentation "The maximum callback request-line octets, including CRLF.")
   (headers :initarg :headers :initform nil :reader client-headers
            :documentation "Additional caller-owned token request headers.")
   (request-function :initarg :request-function :initform nil :reader client-request-function
                     :documentation "An optional HTTP effect taking :url and :content, returning body/status/headers.")
   (request-wrapper :initarg :request-wrapper :initform #'funcall :reader client-request-wrapper
                    :documentation "A thunk wrapper supplying the host's response deadline policy.")
   (credential-function :initarg :credential-function :reader client-credential-function
                        :documentation "The provider's (manager token-document) credential validator.")
   (error-function :initarg :error-function :initform #'browser-authentication-fail
                   :reader client-error-function
                   :documentation "The host's nonreturning failure callback with stage/message/status/code/response keys.")
   (error-type :initarg :error-type :initform 'credential-error :reader client-error-type
               :documentation "Already-safe host condition type propagated intact from request effects.")
   (secret-function :initarg :secret-function :initform cl-rfc8628:*secret-region-function*
                    :reader client-secret-function :documentation "The host's secret-use thunk wrapper.")
   (bounded-string-function :initarg :bounded-string-function :initform #'browser-authentication--bounded-string
                            :reader client-bounded-string-function
                            :documentation "The host's text bounder accepting :limit after secret redaction.")
   (browser-function :initarg :browser-function :initform #'device-authentication-open-browser
                     :reader client-browser-function :documentation "The shared best-effort browser opener.")
   (clock-function :initarg :clock-function :initform #'device-authentication-monotonic-seconds
                   :reader client-clock-function :documentation "A monotonic clock returning seconds.")
   (display-function :initarg :display-function :initform #'browser-authentication--display
                     :reader client-display-function
                     :documentation "The caller's (URL &key redirect-uri timeout stream) login prompt.")
   (browser-failure-function :initarg :browser-failure-function
                             :initform #'browser-authentication--browser-failure
                             :reader client-browser-failure-function
                             :documentation "The caller's manual-browser fallback message function of a stream.")
   (label :initarg :label :initform "OAuth" :reader client-label
          :documentation "A caller-owned product label for safe failure messages.")
   (success-response :initarg :success-response :initform "Authorization received. You may close this tab."
                     :reader client-success-response :documentation "The non-secret callback success body.")
   (failure-response :initarg :failure-response :initform "Authorization failed. Return to the application."
                     :reader client-failure-response :documentation "The non-secret callback failure body.")
   (mismatch-response :initarg :mismatch-response :initform "This callback does not match the active login."
                      :reader client-mismatch-response :documentation "The non-secret unrelated-state response body."))
  (:documentation "Installed-app OAuth endpoints, provider policy, and replaceable host effects."))

(defun browser-authentication--fail (client stage message &key status code response)
  "Signal CLIENT's host condition without retaining transport or callback secrets."
  (funcall (client-error-function client) :stage stage
           :message (format nil "~A: ~A" (client-label client) message)
           :status status :code code :response response)
  (browser-authentication-fail :stage stage :message "The OAuth failure callback returned."))

(defun browser-authentication--validate-timeout (client timeout)
  "Require a finite positive callback or request timeout."
  (unless (and (realp timeout) (< 0 timeout most-positive-fixnum))
    (browser-authentication--fail client ':configuration "OAuth timeouts must be finite positive seconds.")))

(defmethod initialize-instance :after ((client browser-authentication-client) &key)
  "Reject unsafe loopback policy and duplicated protocol parameters."
  (unless (and (client-ports client)
               (listp (client-ports client))
               (every (lambda (port) (typep port '(integer 0 65535))) (client-ports client))
               (member (client-redirect-host client) '("127.0.0.1" "localhost") :test #'equal)
               (stringp (client-callback-path client))
               (plusp (length (client-callback-path client)))
               (char= (char (client-callback-path client) 0) #\/)
               (every (lambda (character)
                        (and (<= 33 (char-code character) 126)
                             (not (find character "?#"))))
                      (client-callback-path client))
               (typep (client-verifier-octets client) '(integer 32 96))
               (typep (client-line-limit client) '(integer 64 65536)))
    (browser-authentication--fail client ':configuration "Invalid OAuth loopback or PKCE configuration."))
  (browser-authentication--validate-timeout client (client-timeout client))
  (browser-authentication--validate-timeout client (client-request-timeout client))
  (dolist (body (list (client-success-response client) (client-failure-response client)
                     (client-mismatch-response client)))
    (unless (and (stringp body) (<= (length (babel:string-to-octets body :encoding ':utf-8)) 4096))
      (browser-authentication--fail client ':configuration "OAuth callback responses must fit in 4096 UTF-8 octets.")))
  (flet ((validate-parameters (parameters reserved)
           (let ((seen nil))
             (dolist (parameter parameters)
               (unless (and (consp parameter) (non-empty-string-p (first parameter))
                            (stringp (rest parameter))
                            (not (member (first parameter) (append reserved seen) :test #'string=)))
                 (browser-authentication--fail client ':configuration "Invalid or repeated OAuth extra parameter."))
               (push (first parameter) seen)))))
    (validate-parameters (client-authorization-parameters client)
                         '("response_type" "client_id" "redirect_uri" "scope" "state"
                           "code_challenge" "code_challenge_method"))
    (validate-parameters (client-token-parameters client)
                         '("grant_type" "client_id" "code" "code_verifier" "redirect_uri"))))

(defun browser-authentication--bounded-string (text &key (limit 256))
  "Return at most LIMIT characters from TEXT."
  (subseq text 0 (min limit (length text))))

(defun browser-authentication--display (url &key redirect-uri timeout stream)
  "Print generic login instructions without a verifier or authorization code."
  (format stream "~&Open this authorization URL:~%  ~A~%Callback: ~A~%Waiting up to ~A seconds.~%"
          url redirect-uri timeout))

(defun browser-authentication--browser-failure (stream)
  "Print the generic manual-browser fallback."
  (format stream "Could not open a browser. Open the URL above manually.~%"))

(defun browser-authentication--base64url (octets)
  "Encode OCTETS as unpadded Base64url."
  (string-right-trim '(#\=)
                     (substitute #\_ #\/ (substitute #\- #\+
                                           (cl-base64:usb8-array-to-base64-string octets)))))

(defun browser-authentication-create-pkce (&key (verifier-octets 32))
  "Return a fresh RFC 7636 verifier and its S256 challenge."
  (unless (typep verifier-octets '(integer 32 96))
    (browser-authentication-fail :stage ':configuration
                                 :message "PKCE requires 32-96 random verifier octets."))
  (let* ((verifier (browser-authentication--base64url (ironclad:random-data verifier-octets)))
         (octets (map '(simple-array (unsigned-byte 8) (*)) #'char-code verifier)))
    (values verifier (browser-authentication--base64url
                      (ironclad:digest-sequence ':sha256 octets)))))

(defun browser-authentication-state ()
  "Return a fresh 256-bit cryptographically random OAuth state."
  (browser-authentication--base64url (ironclad:random-data 32)))

(defun browser-authentication-redacted-value (client value secrets)
  "Redact complete secret occurrences before applying CLIENT's text bound."
  (when (stringp value)
    (let ((secrets (stable-sort (remove-duplicates (remove-if-not #'non-empty-string-p secrets)
                                                  :test #'string=)
                                #'> :key #'length)))
      (funcall (client-bounded-string-function client)
               (redact-exact-string-values
                value secrets (safe-redaction-marker "[OAUTH VALUE REDACTED]" secrets))
               :limit 256))))
