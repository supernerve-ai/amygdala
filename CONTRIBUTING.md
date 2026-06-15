# Contributing to Amygdala

Thanks for your interest in contributing! Amygdala is an open-source project and we welcome contributions of all kinds.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a branch: git checkout -b feature/your-feature
4. Set up your environment:
   `ash
   cp .env.example .env
   pip install -r requirements.txt
   `

## Development Workflow

1. Make your changes in a feature branch
2. Add or update tests in 	ests/
3. Run the test suite: pytest tests/ -v
4. Ensure no secrets are in your diff
5. Commit with a clear message

## Commit Messages

Use clear, descriptive commit messages:
- eat: add IOC feed integration
- ix: handle timeout in MCP client
- docs: update setup instructions
- 	est: add triage agent edge cases

## Pull Requests

- Title format: [amygdala] Short descriptive title
- Describe what changed and why
- Reference any related issues
- Ensure all tests pass before requesting review

## Code Style

- Python 3.12+
- Async-first (use sync/await for I/O)
- Dataclasses for structured results
- Relative imports within the mygdala package
- Logging via logging.getLogger(__name__)
- No hardcoded secrets or magic numbers

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, Docker version)

## Feature Requests

Open an issue describing:
- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

## Security Issues

**Do NOT open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Repository

- GitHub: https://github.com/supernerve-ai/amygdala

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
