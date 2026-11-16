# Recorded registry answer

`hosky_answer.json`: `GET https://tokens.cardano.org/metadata/a0028f350aaabe0545fdcb56b039bfb08e4bb4d8c4d7c3c7d481c235484f534b59`
(HOSKY on mainnet), recorded 2026-11-16, public data, not edited. Status 200,
`content-type: application/json`. The server adds `additionalProperties` and
writes the members of a property in another order than the registry's files do.

Observed the same day, not stored as files because they have no body: an
unknown subject (`.../metadata/zz`, and a well-formed unknown subject) answers
`204 No Content` with an empty body. Older servers answered `404` with plain
text (SPO-12b-PRE-002); that case is hand-written in the test, as are the
oversize, malformed and other-subject answers.
