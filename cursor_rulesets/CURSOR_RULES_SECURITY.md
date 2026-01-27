Here are your three comprehensive rule files:
File 1: CURSOR_RULES_REACT.md
markdown# Cursor AI Development Rules - React/Next.js/TypeScript

## Project Structure & Documentation

1. For every project, create a CHANGES.md file that will track any major changes and features that we make.

2. Follow existing project structure and coding conventions.

3. Keep README.md updated: installation steps, environment variables needed, how to run locally, how to deploy.

4. Include a .env.example file showing required environment variables (without actual values).

## Next.js / React

5. For Next.js projects, use client components for forms, server components for display. Use arrow functions, export default at bottom.

6. Follow App Router conventions: https://nextjs.org/docs/app. Use 'use client' directive only when needed for interactivity.

7. Keep components small and focused. If a component file exceeds 200-250 lines, consider splitting it.

8. Avoid prop drilling beyond 2-3 levels. Use Context API, state management libraries, or component composition instead.

9. Use proper Next.js image optimization: next/image component instead of <img> tags for better performance.

10. Clean up side effects: return cleanup functions in useEffect when dealing with subscriptions, timers, or event listeners.

## CSS / Styling

11. Always use Tailwind v4 syntax and refer to the docs for v4. Never use v3.

12. Mobile-first approach: write base styles for mobile, then use responsive utilities for larger screens (md:, lg:, xl:).

13. Avoid magic numbers: if you're using specific pixel values repeatedly, create Tailwind config variables or CSS custom properties.

## JavaScript / TypeScript

14. Use TypeScript over JavaScript for any React or Next.js projects.

15. Never use "any" type unless absolutely necessary with documented justification.

16. Fix type errors immediately rather than working around them.

17. Do not ignore or suppress TypeScript errors — focus on clean, passing code.

18. Use ES14 syntax: const/let (never var), arrow functions, destructuring, spread operator, template literals, async/await (not .then()), optional chaining (?.), nullish coalescing (??).

19. Naming conventions: camelCase for functions/variables, PascalCase for components/classes/types/interfaces. Be descriptive: calculateUserAge() not calc().

20. Define TypeScript interfaces for all object parameters passed between functions. Use union types and generics appropriately.

21. Validate data shapes at API boundaries. Use Zod, Yup, or similar for runtime type validation in TypeScript.

## Code Quality & Best Practices

22. Write self-documenting code with descriptive naming.

23. Prioritize readability and developer experience.

24. Rigorously apply DRY and KISS principles in all code.

25. DRY & KISS thresholds: code repeated 3+ times → extract to function. Functions >50 lines → split into smaller functions. Max 4 parameters → use object/config. Max 3 nesting levels.

26. One responsibility per function/module. Functions should do exactly what their name says with no surprise side effects.

27. Clean up unused code instead of leaving it "just in case".

28. Eliminate any redundant or speculative elements.

29. Deliver optimal, production-grade code with zero technical debt.

30. Prioritize clean, efficient, and maintainable code.

31. Follow best practices and design patterns appropriate for the language, framework, and project.

32. Write testable code: pure functions, dependency injection, avoid tight coupling. Functions should be easy to unit test.

## Comments & Documentation

33. Explain technical decisions in plain English.

34. If something looks confusing, add a comment explaining why you did it that way.

35. Comment WHY not WHAT. Explain non-obvious decisions, complex logic, and gotchas. Don't comment what code does (self-documenting names handle this).

36. For public functions/APIs, use JSDoc comments to describe parameters, return values, and behavior.

37. Document complex algorithms, business logic, or non-obvious patterns. Include examples in comments when helpful.

## Error Handling

38. Error handling: use try/catch. Validate inputs at function boundaries. Never fail silently - log errors meaningfully.

39. Handle edge cases: null, undefined, empty arrays, empty strings. Don't assume data exists.

## Performance

40. Lazy load components and images when appropriate. Use dynamic imports for code splitting in Next.js/React.

41. Avoid unnecessary re-renders in React: use React.memo(), useMemo(), useCallback() when appropriate. Don't overuse them either.

42. For lists, always include unique, stable key props. Never use array index as key unless list is static and never reordered.

## API & Data Handling

43. Handle loading states, error states, and empty states for all async operations. Never leave users staring at blank screens.

44. Use proper HTTP methods: GET for reading, POST for creating, PUT/PATCH for updating, DELETE for deleting.

45. Validate and sanitize all user inputs. Never trust client-side data.

## Accessibility

46. Use semantic HTML: <button> for buttons, <a> for links, proper heading hierarchy (h1-h6). Never use <div> with onClick for buttons.

47. Include alt text for images, aria-labels for icon buttons, and proper form labels. Ensure keyboard navigation works.

48. Maintain sufficient color contrast (WCAG AA minimum). Test with screen readers when possible.

49. Include test IDs (data-testid) on interactive elements to facilitate automated testing.

## Security

50. Never commit sensitive data: API keys, passwords, tokens, or credentials. Use environment variables (.env files) and add .env to .gitignore.

51. Use proper authentication/authorization checks. Validate on the server side, not just client side.

52. Use different configurations for development, staging, and production. Never use production credentials in development.

## Git & Version Control

53. Write clear, descriptive commit messages: "Add user authentication" not "fix stuff". Use conventional commits format when possible (feat:, fix:, docs:, etc.).

54. Keep commits atomic: one logical change per commit. Don't mix refactoring with feature additions.

55. Before committing, review your changes. Don't commit commented-out code, console.logs, or debug statements.

## Debugging

56. Use meaningful console.log messages during development, but remove or replace with proper logging before production.

## Code Review & Problem Solving

57. Identify potential issues in the code and suggest actionable fixes.

58. Always retrieve to produce high-quality, production-ready code that adheres to modern development principles.

## Workflow & Communication

59. If the task is unclear, ask clarifying questions.

60. Generate concise, actionable responses that minimize disruption to the developer's workflow.

---

## Quick Reference - React/Next.js/TypeScript

### Project Setup
- Create CHANGES.md for tracking
- Include .env.example
- Keep README.md updated

### Next.js Patterns
- Client components for interactivity ('use client')
- Server components for data fetching
- Arrow functions, export default at bottom
- Use next/image for images
- Follow App Router conventions

### TypeScript Standards
- Always TypeScript (never JavaScript)
- Never "any" without justification
- Fix type errors immediately
- Define interfaces for object parameters
- Use Zod/Yup for runtime validation

### ES14 Syntax
- const/let (never var)
- Arrow functions
- Destructuring, spread operator
- Template literals
- async/await (not .then())
- Optional chaining (?.)
- Nullish coalescing (??)

### React Best Practices
- Components <200-250 lines
- No prop drilling >2-3 levels
- Cleanup useEffect side effects
- Unique, stable keys for lists
- Use React.memo/useMemo/useCallback appropriately

### Tailwind v4
- v4 syntax only (never v3)
- Mobile-first approach
- No magic numbers (use config/custom properties)

### Code Quality
- Self-documenting names (camelCase/PascalCase)
- DRY: 3+ repetitions → function
- Functions <50 lines, max 4 params, max 3 nesting
- One responsibility per function
- Comment WHY not WHAT
- Clean up unused code

### Performance
- Lazy load components/images
- Code splitting with dynamic imports
- Avoid unnecessary re-renders

### Accessibility
- Semantic HTML (<button>, <a>, proper headings)
- Alt text, aria-labels, form labels
- WCAG AA color contrast
- Keyboard navigation

### API/Data
- Handle loading/error/empty states
- Proper HTTP methods
- Validate inputs
- Handle edge cases (null, undefined, empty)

### Security
- Never commit secrets (use .env)
- Validate server-side
- Different configs for dev/staging/prod

### Git
- Clear commit messages (conventional commits)
- Atomic commits
- Review before committing
File 2: CURSOR_RULES_PYTHON.md
markdown# Cursor AI Development Rules - Python/Data Science

## Project Structure & Documentation

1. For every project, create a CHANGES.md file that will track any major changes and features that we make.

2. Follow existing project structure and coding conventions.

3. Keep README.md updated: installation steps, dependencies (requirements.txt or pyproject.toml), how to run locally, environment setup.

4. Include a .env.example file showing required environment variables (without actual values).

5. Include requirements.txt or pyproject.toml with pinned versions for reproducibility.

## Python Standards (3.11+)

6. Follow PEP 8: snake_case for functions/variables, PascalCase for classes. Always use type hints for parameters and return values: def get_user(id: int) -> User:.

7. Use modern Python 3.11+ features: match statements, union types with |, f-strings for formatting.

8. Use type hints for all function parameters and return values. Example: def process_data(df: pd.DataFrame, threshold: float = 0.5) -> pd.DataFrame:

9. Use union types: str | None instead of Optional[str].

## Code Quality & Best Practices

10. Write self-documenting code with descriptive naming.

11. Prioritize readability and developer experience.

12. Rigorously apply DRY and KISS principles in all code.

13. DRY & KISS thresholds: code repeated 3+ times → extract to function. Functions >50 lines → split into smaller functions. Max 4 parameters → use dataclass/dict/config. Max 3 nesting levels.

14. One responsibility per function/module. Functions should do exactly what their name says with no surprise side effects.

15. Clean up unused code instead of leaving it "just in case".

16. Eliminate any redundant or speculative elements.

17. Deliver optimal, production-grade code with zero technical debt.

18. Prioritize clean, efficient, and maintainable code.

19. Follow best practices and design patterns appropriate for Python and the specific libraries being used.

20. Write testable code: pure functions, dependency injection, avoid tight coupling. Functions should be easy to unit test.

## Pandas

21. Prefer vectorized operations over loops: df['new_col'] = df['col1'] * 2 instead of iterating rows. Use method chaining for readability. Avoid inplace=True unless memory constrained.

22. Use meaningful column names. Document data transformations in comments when not obvious.

23. Handle missing data explicitly: document assumptions about NaN handling, use appropriate fill strategies.

24. For large datasets, be mindful of memory usage. Use appropriate dtypes (category for categorical data, int32 instead of int64 when possible).

25. Chain operations for clarity: df.query('age > 18').groupby('category')['value'].sum().sort_values(ascending=False)

## NumPy

26. Always use vectorized operations. Check array shapes are compatible. Never iterate over arrays when broadcasting/vectorization is possible.

27. Document array shapes in comments for complex operations: # shape: (n_samples, n_features)

28. Use appropriate dtypes to save memory: float32 instead of float64 when precision allows.

29. Leverage broadcasting rules. Comment when broadcasting behavior is non-obvious.

## Data Science Workflow

30. Include data validation checks: assert statements for data shape, range checks, null checks.

31. Set random seeds for reproducibility: np.random.seed(42), random.seed(42), tf.random.set_seed(42)

32. Document model hyperparameters, assumptions, and data preprocessing steps.

33. For exploratory analysis, use Jupyter notebooks. For production code, convert to .py modules.

34. Save model artifacts, preprocessing pipelines, and configurations for reproducibility.

## Comments & Documentation

35. Explain technical decisions in plain English.

36. If something looks confusing, add a comment explaining why you did it that way.

37. Comment WHY not WHAT. Explain non-obvious decisions, complex logic, and gotchas. Don't comment what code does (self-documenting names handle this).

38. Use docstrings for functions and classes following Google or NumPy style guide.

39. Document complex algorithms, business logic, or non-obvious patterns. Include examples in docstrings when helpful.

40. For data science projects, document: data sources, feature engineering steps, model selection rationale, evaluation metrics used.

## Error Handling

41. Error handling: use try/except. Validate inputs at function boundaries. Never fail silently - log errors meaningfully or raise informative exceptions.

42. Handle edge cases: None, empty lists, empty DataFrames, invalid data types. Don't assume data exists or is valid.

43. For data pipelines, implement graceful degradation or clear failure modes.

## Performance

44. Profile code before optimizing. Use cProfile, line_profiler, or memory_profiler to identify bottlenecks.

45. For large datasets, consider: chunking data, using Dask for out-of-core computation, or polars for faster operations.

46. Vectorize operations. Avoid Python loops over large arrays/DataFrames.

## Testing & Validation

47. Write unit tests for data processing functions. Test edge cases (empty data, single row, all nulls).

48. Include data quality checks: schema validation, range checks, consistency checks.

49. For ML models, include: train/test split, cross-validation, appropriate evaluation metrics.

## Security & Data Privacy

50. Never commit sensitive data: credentials, API keys, or actual datasets. Use environment variables and .gitignore.

51. Be mindful of data privacy: anonymize PII, follow data governance policies, document data retention.

52. For database queries, use parameterized queries or ORMs to prevent SQL injection. Never concatenate user input into queries.

## Environment & Dependencies

53. Use virtual environments: venv, conda, or poetry. Document environment setup in README.

54. Pin dependency versions in requirements.txt for reproducibility.

55. Use different configurations for development, staging, and production. Never use production credentials in development.

## Git & Version Control

56. Write clear, descriptive commit messages: "Add feature engineering for user demographics" not "update notebook". Use conventional commits format when possible (feat:, fix:, docs:, etc.).

57. Keep commits atomic: one logical change per commit. Don't mix refactoring with feature additions.

58. Before committing, review your changes. Clean up commented-out code, print statements, and debug cells in notebooks.

59. Don't commit large data files. Use .gitignore for data directories. Document where data should be placed.

## Jupyter Notebooks

60. Keep notebooks focused: one notebook per analysis or experiment.

61. Clear outputs before committing notebooks (unless outputs are essential for documentation).

62. Use markdown cells to explain analysis steps, insights, and decisions.

63. Restart kernel and run all cells before sharing to ensure reproducibility.

## Code Review & Problem Solving

64. Identify potential issues in the code and suggest actionable fixes.

65. Always retrieve to produce high-quality, production-ready code that adheres to modern development principles.

## Workflow & Communication

66. If the task is unclear, ask clarifying questions.

67. Generate concise, actionable responses that minimize disruption to the developer's workflow.

---

## Quick Reference - Python/Data Science

### Project Setup
- Create CHANGES.md for tracking
- Include requirements.txt or pyproject.toml
- Include .env.example
- Keep README.md updated
- Use virtual environments

### Python Standards (3.11+)
- PEP 8: snake_case functions/variables, PascalCase classes
- Always use type hints: def func(x: int) -> str:
- Union types with |: str | None
- f-strings for formatting
- Match statements for complex conditionals

### Pandas Best Practices
- Vectorize operations: df['col'] * 2 (not loops)
- Method chaining for clarity
- Avoid inplace=True unless memory constrained
- Handle missing data explicitly
- Use appropriate dtypes (category, int32)
- Document transformations

### NumPy Best Practices
- Always vectorize (never iterate)
- Check array shapes
- Use broadcasting
- Document shapes: # shape: (n, m)
- Use appropriate dtypes (float32 when possible)

### Data Science Workflow
- Set random seeds for reproducibility
- Validate data: assert shapes, check nulls
- Document hyperparameters and preprocessing
- Save model artifacts and configs
- Use notebooks for exploration, .py for production

### Code Quality
- Self-documenting names (snake_case)
- DRY: 3+ repetitions → function
- Functions <50 lines, max 4 params, max 3 nesting
- One responsibility per function
- Comment WHY not WHAT
- Clean up unused code
- Use docstrings (Google/NumPy style)

### Performance
- Profile before optimizing
- Vectorize operations
- Consider Dask/polars for large data
- Chunk large datasets

### Testing & Validation
- Unit tests for data processing
- Test edge cases (empty, single row, nulls)
- Data quality checks (schema, ranges)
- ML: train/test split, cross-validation, metrics

### Security & Privacy
- Never commit secrets or data (use .env)
- Anonymize PII
- Parameterized queries (prevent SQL injection)
- Follow data governance

### Jupyter Notebooks
- One notebook per analysis
- Clear outputs before committing
- Use markdown for explanations
- Restart kernel and run all before sharing

### Git
- Clear commit messages (conventional commits)
- Atomic commits
- Clean up before committing
- .gitignore for data files
File 3: CURSOR_RULES_SECURITY.md
markdown# Cursor AI Development Rules - Security & Best Practices

## Critical Security Rules

These rules apply to ALL projects regardless of language or framework.

## Secrets & Credentials Management

1. **NEVER commit sensitive data**: API keys, passwords, tokens, credentials, private keys, or any secrets. Use environment variables (.env files) and add .env to .gitignore. **Exception**: For Azure Functions projects, use `local.settings.json` instead of `.env` files (see CURSOR_RULES_AZURE.md).

2. **Include configuration template**: Create a template showing required environment variables without actual values. Use `.env.example` for standard projects, or `local.settings.json.template` for Azure Functions projects.
```
   # .env.example (standard projects)
   API_KEY=your_api_key_here
   DATABASE_URL=your_database_url_here
   
   # OR local.settings.json.template (Azure Functions)
   {
     "Values": {
       "API_KEY": "your_api_key_here",
       "DATABASE_URL": "your_database_url_here"
     }
   }
```

3. **Use different credentials for each environment**: Never use production credentials in development or staging. Keep environments isolated.

4. **Rotate secrets regularly**: Especially after team member departures or suspected compromise.

5. **Use secret management tools**: For production, use AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, or similar. Never hardcode production secrets.

## Input Validation & Sanitization

6. **Validate ALL user inputs**: Never trust client-side data. Validate on the server side.

7. **Sanitize user inputs**: Strip or escape potentially dangerous characters before processing or storing data.

8. **Whitelist over blacklist**: Define what IS allowed rather than trying to block what ISN'T. Blacklists are incomplete.

9. **Type validation**: Ensure data matches expected types. Use TypeScript interfaces, Pydantic models, or JSON schemas.

10. **Range and format validation**: Check that numbers are in acceptable ranges, strings match expected patterns (email, phone, etc.).

## Authentication & Authorization

11. **Server-side authentication**: Never rely solely on client-side checks. Always verify on the server.

12. **Principle of least privilege**: Users should only have access to what they need. Check authorization on every protected operation.

13. **Use established auth libraries**: Don't roll your own authentication. Use NextAuth.js, Passport.js, Django Auth, etc.

14. **Secure session management**: Use httpOnly cookies, secure flags, appropriate expiration times.

15. **Multi-factor authentication**: Implement or support MFA for sensitive operations.

## Database Security

16. **Use parameterized queries or ORMs**: NEVER concatenate user input into SQL queries. Prevents SQL injection.
```javascript
   // BAD - SQL injection vulnerability
   const query = `SELECT * FROM users WHERE id = ${userId}`;
   
   // GOOD - parameterized query
   const query = 'SELECT * FROM users WHERE id = ?';
   db.query(query, [userId]);
```

17. **Principle of least privilege for DB access**: Application database users should only have necessary permissions.

18. **Encrypt sensitive data at rest**: PII, financial data, health information should be encrypted in the database.

19. **Use connection pooling securely**: Don't expose database connection strings in logs or error messages.

## API Security

20. **Rate limiting**: Implement rate limiting on all public APIs to prevent abuse and DoS attacks.

21. **Use HTTPS only**: Never transmit sensitive data over HTTP. Enforce HTTPS in production.

22. **CORS configuration**: Be specific about allowed origins. Never use `*` in production.

23. **API key security**: If using API keys, rotate them regularly, use different keys for different services, never expose in client code.

24. **Input size limits**: Limit request body sizes, file upload sizes, and query parameter lengths to prevent DoS.

## Frontend Security

25. **XSS prevention**: Sanitize user-generated content before rendering. Use frameworks that escape by default (React does this).

26. **Content Security Policy (CSP)**: Implement CSP headers to prevent XSS and injection attacks.

27. **Avoid eval() and similar**: Never use eval(), Function constructor, or innerHTML with user data.

28. **Secure localStorage/sessionStorage usage**: Don't store sensitive data (tokens, passwords) in localStorage. Use httpOnly cookies instead.

## Dependency Security

29. **Keep dependencies updated**: Regularly update packages to patch security vulnerabilities.

30. **Audit dependencies**: Run `npm audit`, `pip-audit`, or similar regularly. Fix critical vulnerabilities immediately.

31. **Review dependencies before adding**: Check package popularity, maintenance status, and security history before adding new dependencies.

32. **Lock file usage**: Commit package-lock.json, yarn.lock, or poetry.lock to ensure consistent dependency versions.

## Error Handling & Logging

33. **Never expose stack traces in production**: Users shouldn't see detailed error messages. Log them server-side instead.

34. **Sanitize error messages**: Don't leak sensitive information (paths, database structure, internal IPs) in error messages.

35. **Log security events**: Log authentication attempts, authorization failures, unusual access patterns.

36. **Secure logging**: Don't log sensitive data (passwords, tokens, credit cards, SSNs). Redact if necessary.

## File Upload Security

37. **Validate file types**: Check both extension AND content type (magic bytes). Don't trust client-provided MIME types.

38. **Limit file sizes**: Prevent DoS through large file uploads.

39. **Scan for malware**: Use antivirus scanning for user-uploaded files.

40. **Store uploads outside webroot**: Uploaded files shouldn't be directly accessible via URL without authorization check.

41. **Generate random filenames**: Don't use user-provided filenames. Generate random names to prevent path traversal attacks.

## Data Privacy & Compliance

42. **Minimal data collection**: Only collect data you actually need. Follow data minimization principles.

43. **Anonymize PII**: Personal Identifiable Information should be anonymized in logs, analytics, and non-production environments.

44. **Data retention policies**: Delete data when no longer needed. Document retention policies.

45. **GDPR/CCPA compliance**: If applicable, implement right to access, right to deletion, data portability.

46. **Secure data transmission**: Use TLS 1.2+ for all data in transit. Disable older protocols.

## Session & Token Security

47. **Short-lived tokens**: Use short expiration times for access tokens. Implement refresh token rotation.

48. **Token storage**: Store tokens securely (httpOnly cookies or secure storage, never localStorage for sensitive tokens).

49. **Logout implementation**: Properly invalidate sessions/tokens on logout. Clear client-side storage.

50. **CSRF protection**: Implement CSRF tokens for state-changing operations.

## Security Testing

51. **Security testing in CI/CD**: Include security scans (SAST, dependency checks) in your pipeline.

52. **Penetration testing**: For production applications, conduct regular penetration testing.

53. **Code review for security**: Security-focused code reviews for authentication, authorization, and data handling code.

## Incident Response

54. **Have a plan**: Document incident response procedures. Who to contact, what to do.

55. **Monitor for anomalies**: Set up alerts for unusual activity (failed login attempts, unusual API usage, etc.).

56. **Security updates**: Have a process for quickly deploying security patches.

## Documentation

57. **Document security decisions**: Explain why certain security measures were chosen, what threats they mitigate.

58. **Security onboarding**: New team members should be trained on security practices.

59. **Threat modeling**: For complex features, document potential threats and mitigations.

## Git & Version Control Security

60. **Scan commits for secrets**: Use tools like git-secrets, truffleHog, or GitGuardian to catch accidentally committed secrets.

61. **Review commit history**: Before open-sourcing, audit entire history for secrets.

62. **Protected branches**: Require reviews for main/production branches. Prevent force pushes.

## Cloud & Infrastructure Security

63. **Principle of least privilege for cloud**: IAM roles should have minimal necessary permissions.

64. **Network segmentation**: Use VPCs, security groups, and firewalls appropriately.

65. **Backup security**: Encrypt backups. Test restoration procedures. Store backups securely.

66. **Regular security audits**: Review cloud configurations, access logs, and permissions regularly.

---

## Security Checklist by Phase

### Before Writing Code
- [ ] Understand data sensitivity and compliance requirements
- [ ] Plan authentication and authorization strategy
- [ ] Set up secret management (environment variables, or local.settings.json for Azure Functions)
- [ ] Configure .gitignore to exclude secrets and sensitive files (.env or local.settings.json)

### During Development
- [ ] Validate ALL user inputs server-side
- [ ] Use parameterized queries or ORMs
- [ ] Implement proper error handling (no stack traces to users)
- [ ] Use established auth libraries
- [ ] Never hardcode secrets
- [ ] Sanitize data before rendering
- [ ] Implement rate limiting on APIs

### Before Deployment
- [ ] Audit dependencies (`npm audit`, `pip-audit`)
- [ ] Review code for security issues
- [ ] Ensure HTTPS is enforced
- [ ] Configure CSP headers
- [ ] Set up proper CORS
- [ ] Test authentication and authorization
- [ ] Verify secrets are not in code or version control
- [ ] Set up logging and monitoring

### Production Monitoring
- [ ] Monitor for unusual activity
- [ ] Regularly update dependencies
- [ ] Review access logs
- [ ] Rotate credentials periodically
- [ ] Conduct security audits

## Quick Reference by Threat

### SQL Injection Prevention
- Use parameterized queries or ORMs
- Never concatenate user input into queries
- Validate input types and formats

### XSS Prevention
- Use frameworks that escape by default
- Sanitize user-generated content
- Implement CSP headers
- Never use eval() or innerHTML with user data

### Authentication Bypass Prevention
- Server-side verification always
- Short-lived tokens with refresh rotation
- Secure session management
- MFA for sensitive operations

### Data Breach Prevention
- Encrypt sensitive data at rest and in transit
- Principle of least privilege
- Never commit secrets
- Anonymize PII in non-production
- Regular security audits

### DoS Prevention
- Rate limiting on all APIs
- Input size limits
- File size limits
- Timeout configurations

### CSRF Prevention
- CSRF tokens for state-changing operations
- SameSite cookie attributes
- Verify origin headers