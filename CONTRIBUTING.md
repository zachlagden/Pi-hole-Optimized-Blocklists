# Contributing

Contributions are welcome. This document covers the basics.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat(scope): add new feature
   fix(scope): resolve bug with X
   docs: update installation steps
   ```
5. Push to your fork and open a Pull Request

## Branch Naming

| Prefix | Use |
| --- | --- |
| `feature/<description>` | New features |
| `fix/<description>` | Bug fixes |
| `hotfix/<description>` | Urgent production fixes |
| `refactor/<description>` | Code improvements |
| `chore/<description>` | Maintenance tasks |

## Code Standards

- Write clear, readable code over clever code
- Follow existing patterns in the codebase
- Keep functions short and focused
- Add comments explaining **why**, not **what**
- Handle errors explicitly

## Pull Requests

- Keep PRs focused on a single change
- Write a clear title following conventional commit format
- Fill in the PR template
- Make sure CI passes before requesting review
- Respond to review feedback promptly

## Reporting Issues

Use the issue templates provided:

- **Bug Report** -- for bugs and unexpected behaviour
- **Feature Request** -- for new ideas and improvements
- **False Positive Report** -- for domains that shouldn't be blocked

Include as much detail as possible. Steps to reproduce are essential for bug reports.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
