## Summary

Describe the behavior changed and why.

## Security boundary

- What independently enforces the behavior?
- What paths remain outside the boundary?
- What happens on policy, parser, storage, or adapter failure?

## Validation

- [ ] `uv run ruff check src tests`
- [ ] `uv run pytest -q`
- [ ] `pnpm typecheck`
- [ ] `pnpm test`
- [ ] `pnpm build`
- [ ] Reviewed changed files for credentials, personal data, logs, fixtures, and generated output

List exact results and any checks not run. Do not claim a security audit or certification based only on passing tests.

## Documentation and limitations

List updated docs and clearly state any partial or unverified behavior.
