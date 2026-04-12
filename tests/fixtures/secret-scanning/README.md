These files hold **intentionally fake** data for YARA secret-detection unit tests.

- **Plaintext** samples may live here only when listed in `.github/secret_scanning.yml` (`paths-ignore`).
- **Slack-shaped** vectors use `*.utf8.decimals` (comma-separated UTF-8 code units) so push protection does not match token regexes on file contents.

Do not put real credentials here.
