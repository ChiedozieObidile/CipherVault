;; CipherVault - Decentralized Identity Management Contract
;; This contract enables users to control their digital presence while preserving confidentiality
;; through cryptographic methods and controlled information sharing

;; Error codes
(define-constant ERR-ACCESS-DENIED (err u100))
(define-constant ERR-PROFILE-EXISTS (err u101))
(define-constant ERR-PROFILE-NOT-FOUND (err u102))
(define-constant ERR-INVALID-PROOF (err u103))
(define-constant ERR-ATTESTATION-EXPIRED (err u104))
(define-constant ERR-INVALID-PARAMETER (err u105))

;; Constants for validation
(define-constant MIN-TIME-VALUE u1)
(define-constant MAX-TIME-VALUE u9999999999)

;; Data Maps
(define-map profiles
    principal
    {
        profile-hash: (buff 32),
        creation-time: uint,
        attestations: (list 10 (buff 32)),
        encryption-key: (buff 33),
        profile-deactivated: bool
    }
)

(define-map attestation-registry
    (buff 32)  ;; attestation hash
    {
        issuer: principal,
        issue-time: uint,
        valid-until: uint,
        attestation-type: (string-utf8 64),
        attestation-revoked: bool
    }
)

(define-map verification-requests
    (buff 32)  ;; verification request ID
    {
        verifier: principal,
        requested-fields: (list 5 (string-utf8 64)),
        request-approved: bool,
        cryptographic-proof: (buff 32)
    }
)

;; Private functions
(define-private (validate-proof 
    (submitted-proof (buff 32)) 
    (stored-hash (buff 32)))
    (is-eq submitted-proof stored-hash)
)

(define-private (check-attestation-status 
    (attestation-hash (buff 32))
    (attestation-data {
        issuer: principal, 
        issue-time: uint, 
        valid-until: uint, 
        attestation-type: (string-utf8 64), 
        attestation-revoked: bool
    }))
    (and
        (< block-height (get valid-until attestation-data))
        (not (get attestation-revoked attestation-data))
    )
)

(define-private (validate-time-value (time-value uint))
    (and 
        (>= time-value MIN-TIME-VALUE)
        (<= time-value MAX-TIME-VALUE)
    )
)

(define-private (validate-hash (input (buff 32)))
    (is-eq (len input) u32)
)

(define-private (validate-pubkey (input (buff 33)))
    (is-eq (len input) u33)
)

;; Public functions
(define-public (register-profile 
    (encryption-key (buff 33)) 
    (profile-hash (buff 32)))
    (let
        ((current-user tx-sender))
        (asserts! (validate-pubkey encryption-key) ERR-INVALID-PARAMETER)
        (asserts! (validate-hash profile-hash) ERR-INVALID-PARAMETER)
        (asserts! (is-none (map-get? profiles current-user)) ERR-PROFILE-EXISTS)
        (ok (map-set profiles
            current-user
            {
                profile-hash: profile-hash,
                creation-time: block-height,
                attestations: (list),
                encryption-key: encryption-key,
                profile-deactivated: false
            }
        ))
    )
)

(define-public (add-attestation 
    (attestation-hash (buff 32))
    (valid-until uint)
    (attestation-type (string-utf8 64)))
    (let
        ((current-user tx-sender)
         (user-profile (unwrap! (map-get? profiles current-user) ERR-PROFILE-NOT-FOUND)))
        (asserts! (validate-hash attestation-hash) ERR-INVALID-PARAMETER)
        (asserts! (validate-time-value valid-until) ERR-INVALID-PARAMETER)
        (asserts! (> valid-until block-height) ERR-ATTESTATION-EXPIRED)
        (asserts! (not (get profile-deactivated user-profile)) ERR-ACCESS-DENIED)
        (map-set attestation-registry
            attestation-hash
            {
                issuer: current-user,
                issue-time: block-height,
                valid-until: valid-until,
                attestation-type: attestation-type,
                attestation-revoked: false
            }
        )
        (ok (map-set profiles
            current-user
            (merge user-profile
                {attestations: (unwrap! (as-max-len? (append (get attestations user-profile) attestation-hash) u10)
                    ERR-ACCESS-DENIED)}
            )
        ))
    )
)

(define-public (create-verification-request
    (request-id (buff 32))
    (required-fields (list 5 (string-utf8 64))))
    (let
        ((requesting-entity tx-sender))
        (asserts! (validate-hash request-id) ERR-INVALID-PARAMETER)
        (asserts! (not (is-none (map-get? verification-requests request-id))) ERR-INVALID-PARAMETER)
        (ok (map-set verification-requests
            request-id
            {
                verifier: requesting-entity,
                requested-fields: required-fields,
                request-approved: false,
                cryptographic-proof: 0x00
            }
        ))
    )
)

(define-public (approve-verification
    (request-id (buff 32))
    (cryptographic-proof (buff 32)))
    (let
        ((current-user tx-sender)
         (verification-request (unwrap! (map-get? verification-requests request-id) ERR-ACCESS-DENIED))
         (user-profile (unwrap! (map-get? profiles current-user) ERR-PROFILE-NOT-FOUND)))
        (asserts! (validate-hash request-id) ERR-INVALID-PARAMETER)
        (asserts! (validate-hash cryptographic-proof) ERR-INVALID-PARAMETER)
        (asserts! (not (get profile-deactivated user-profile)) ERR-ACCESS-DENIED)
        (asserts! (validate-proof cryptographic-proof (get profile-hash user-profile)) ERR-INVALID-PROOF)
        (ok (map-set verification-requests
            request-id
            (merge verification-request
                {
                    request-approved: true,
                    cryptographic-proof: cryptographic-proof
                }
            )
        ))
    )
)

(define-public (revoke-attestation (attestation-hash (buff 32)))
    (let
        ((current-user tx-sender)
         (attestation-data (unwrap! (map-get? attestation-registry attestation-hash) ERR-ACCESS-DENIED)))
        (asserts! (validate-hash attestation-hash) ERR-INVALID-PARAMETER)
        (asserts! (is-eq (get issuer attestation-data) current-user) ERR-ACCESS-DENIED)
        (ok (map-set attestation-registry
            attestation-hash
            (merge attestation-data {attestation-revoked: true})
        ))
    )
)

(define-public (update-profile 
    (new-profile-hash (buff 32)) 
    (new-encryption-key (buff 33)))
    (let
        ((current-user tx-sender)
         (existing-profile (unwrap! (map-get? profiles current-user) ERR-PROFILE-NOT-FOUND)))
        (asserts! (validate-hash new-profile-hash) ERR-INVALID-PARAMETER)
        (asserts! (validate-pubkey new-encryption-key) ERR-INVALID-PARAMETER)
        (asserts! (not (get profile-deactivated existing-profile)) ERR-ACCESS-DENIED)
        (ok (map-set profiles
            current-user
            (merge existing-profile
                {
                    profile-hash: new-profile-hash,
                    encryption-key: new-encryption-key
                }
            )
        ))
    )
)

;; Read-only functions
(define-read-only (get-profile (user-principal principal))
    (map-get? profiles user-principal)
)

(define-read-only (get-attestation-data (attestation-hash (buff 32)))
    (map-get? attestation-registry attestation-hash)
)

(define-read-only (verify-request
    (request-id (buff 32))
    (submitted-proof (buff 32)))
    (match (map-get? verification-requests request-id)
        request-data (and
            (get request-approved request-data)
            (validate-proof submitted-proof (get cryptographic-proof request-data))
        )
        false
    )
)

(define-read-only (check-attestation-validity (attestation-hash (buff 32)))
    (match (map-get? attestation-registry attestation-hash)
        attestation-data (check-attestation-status attestation-hash attestation-data)
        false
    )
)