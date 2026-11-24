# Semgrep with rule packs baked in (OQ-14, decided 2026-11-24), so scans run with --network none and never fetch
# rules at scan time. Built in CI; the built image's digest goes into images.lock only after review, and that digest
# is what pins the rule content (the registry URLs below are not versioned).
# Licence: registry rules are under the Semgrep Rules License v1.0: fine for internal scanning of company code; do
# not offer this platform's scanning to third parties without a licence review.
# p/typescript is byte-identical to p/javascript (checked 2026-11-24), so it is not added twice.
# No Dart/Flutter pack exists in the registry; Flutter code gets dependency and secret scanning only.
FROM semgrep/semgrep@sha256:6e1b04340e60e910fbb4ddbf3c857ab0918f064417ad5ac530014ccb3cf8c8f1
ADD --chmod=644 https://semgrep.dev/c/p/default /rules/default.yml
ADD --chmod=644 https://semgrep.dev/c/p/owasp-top-ten /rules/owasp-top-ten.yml
ADD --chmod=644 https://semgrep.dev/c/p/secrets /rules/secrets.yml
ADD --chmod=644 https://semgrep.dev/c/p/javascript /rules/javascript.yml
ADD --chmod=644 https://semgrep.dev/c/p/python /rules/python.yml
ADD --chmod=644 https://semgrep.dev/c/p/php /rules/php.yml
ADD --chmod=644 https://semgrep.dev/c/p/kotlin /rules/kotlin.yml
ADD --chmod=644 https://semgrep.dev/c/p/swift /rules/swift.yml
ADD --chmod=644 https://semgrep.dev/c/p/dockerfile /rules/dockerfile.yml
ADD --chmod=644 https://semgrep.dev/c/p/github-actions /rules/github-actions.yml
USER 10001
ENTRYPOINT []
