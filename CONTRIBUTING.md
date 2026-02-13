# Contributing to Tailscale JIT Access Management

Thanks for your interest in contributing! This project is meant to stay lightweight and focused, so here's how to help effectively.

## Ways to Contribute

- **Bug reports**: Open an issue with steps to reproduce
- **Feature requests**: Open an issue describing the use case
- **Documentation**: Improvements to README, QUICKSTART, or inline comments
- **Code**: Bug fixes, security improvements, new features

## Development Setup

```bash
# Clone the repo
git clone https://github.com/ccatprd/tailscale-jit-access.git
cd tailscale-jit-access

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your Tailscale credentials

# Run development server
python3 app.py
```

## Code Guidelines

- **Keep it simple**: This is a lightweight tool, not an enterprise SaaS platform
- **Python style**: Follow existing code conventions (PEP 8, type hints where helpful)
- **Security first**: All inputs must be validated, all actions must be audited
- **No new dependencies** without strong justification: every dependency is an attack surface
- **Test your changes** against a real Tailscale tailnet before submitting

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes
4. Test against a real Tailscale tailnet
5. Submit a pull request with a clear description of what changed and why

## Architecture Decisions

- **SQLite over Postgres**: Simplicity for single-node deployments. No connection pool needed.
- **Flask over FastAPI**: Simpler, wider ecosystem for Jinja2 templates, adequate for this workload.
- **Tailscale Serve for auth**: We never handle passwords. Authentication is entirely Tailscale's responsibility.
- **Server-side rendering**: No React/Vue/SPA. Simple Jinja2 templates keep the deployment trivial.

## Security Reports

If you find a security vulnerability, please **do not** open a public issue. Email the maintainers directly instead.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
