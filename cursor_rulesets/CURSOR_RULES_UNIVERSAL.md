# Cursor AI Development Rules - Universal (All Languages & Projects)

These rules apply to ALL projects regardless of language, framework, or platform.

## Project Structure & Documentation

1. For every project, create a CHANGES.md file that will track any major changes and features that we make.

2. Follow existing project structure and coding conventions.

3. Keep README.md updated: installation steps, dependencies, how to run locally, how to deploy, environment setup.

4. Include environment variable template file (.env.example, config.example.json, etc.) showing required variables without actual values. **Exception**: For Azure Functions projects, use `local.settings.json.template` instead of `.env.example` (see CURSOR_RULES_AZURE.md).

5. Document dependencies with version pinning (package-lock.json, requirements.txt, Gemfile.lock, etc.).

## Code Quality & Best Practices

6. Write self-documenting code with descriptive naming.

7. Prioritize readability and developer experience.

8. Rigorously apply DRY and KISS principles in all code.

9. DRY & KISS thresholds: code repeated 3+ times → extract to function. Functions >50 lines → split into smaller functions. Max 4 parameters → use object/config/struct. Max 3 nesting levels.

10. One responsibility per function/module. Functions should do exactly what their name says with no surprise side effects.

11. Clean up unused code instead of leaving it "just in case".

12. Eliminate any redundant or speculative elements.

13. Deliver optimal, production-grade code with zero technical debt.

14. Prioritize clean, efficient, and maintainable code.

15. Follow best practices and design patterns appropriate for the language, framework, and project.

16. Write testable code: pure functions, dependency injection, avoid tight coupling. Functions should be easy to unit test.

## Comments & Documentation

17. Explain technical decisions in plain English.

18. If something looks confusing, add a comment explaining why you did it that way.

19. Comment WHY not WHAT. Explain non-obvious decisions, complex logic, and gotchas. Don't comment what code does (self-documenting names handle this).

20. Document complex algorithms, business logic, or non-obvious patterns. Include examples in comments when helpful.

21. For public functions/APIs/modules, use appropriate documentation format for the language (JSDoc, docstrings, XML comments, etc.) to describe parameters, return values, and behavior.

## Error Handling

22. Implement proper error handling using language-appropriate mechanisms (try/catch, Result types, Option types, exceptions, etc.).

23. Validate inputs at function boundaries. Never trust external data.

24. Never fail silently - log errors meaningfully or propagate them appropriately.

25. Handle edge cases: null/nil/None, undefined, empty collections, zero values, negative numbers where unexpected. Don't assume data exists or is valid.

## Code Review & Problem Solving

26. Identify potential issues in the code and suggest actionable fixes.

27. Always strive to produce high-quality, production-ready code that adheres to modern development principles.

## Workflow & Communication

28. If the task is unclear, ask clarifying questions before writing code.

29. Generate concise, actionable responses that minimize disruption to the developer's workflow.

## Git & Version Control

30. Write clear, descriptive commit messages: "Add user authentication" not "fix stuff". Use conventional commits format when possible (feat:, fix:, docs:, refactor:, test:, chore:).

31. Keep commits atomic: one logical change per commit. Don't mix refactoring with feature additions.

32. Before committing, review your changes. Don't commit commented-out code, debug statements, or temporary files.

33. Use .gitignore appropriately: exclude build artifacts, dependencies (node_modules, venv, etc.), IDE files, OS files (.DS_Store), logs, and sensitive data.

## Testing

34. Write unit tests for critical business logic and complex functions.

35. Test edge cases: empty inputs, null values, boundary conditions, error conditions.

36. Include integration tests for important workflows.

37. Tests should be readable and serve as documentation of expected behavior.

## Performance

38. Profile before optimizing. Measure actual performance bottlenecks rather than guessing.

39. Avoid premature optimization. Optimize only when there's a proven performance issue.

40. Be mindful of algorithmic complexity. Avoid O(n²) or worse when better solutions exist.

## Debugging

41. Use appropriate debugging tools for the language/platform rather than excessive print/log statements.

42. During development, debug statements are fine. Remove or replace with proper logging before production.

43. Write meaningful log messages that help diagnose issues. Include relevant context.

## Naming Conventions (Language-Specific)

44. Follow the naming conventions of the language ecosystem:
    - JavaScript/TypeScript: camelCase for variables/functions, PascalCase for classes/components
    - Python: snake_case for functions/variables, PascalCase for classes
    - Ruby: snake_case for methods/variables, PascalCase for classes
    - C#/Java: camelCase for variables, PascalCase for classes/methods
    - Go: MixedCaps or mixedCaps based on visibility
    - Rust: snake_case for functions/variables, PascalCase for types
    - Be consistent within the project

45. Be descriptive: calculateUserAge() not calc(), getUserById() not getUser(), processPaymentTransaction() not process().

## Accessibility (When Applicable)

46. For user-facing applications, follow accessibility best practices for the platform (WCAG for web, platform guidelines for mobile).

47. Ensure keyboard navigation works properly (web/desktop apps).

48. Provide appropriate labels, descriptions, and alt text for UI elements.

## Environment & Configuration

49. Use different configurations for development, staging, and production. Never use production credentials in development.

50. Externalize configuration. Don't hardcode environment-specific values.

51. Provide sensible defaults where appropriate, but allow overrides via environment variables or config files.

## Dependencies

52. Keep dependencies updated to patch security vulnerabilities and bugs.

53. Review dependencies before adding: check maintenance status, popularity, license, and security history.

54. Minimize dependencies. Don't add large libraries for trivial functionality.

55. Lock dependency versions for reproducibility (lock files).

## Project Organization

56. Organize by feature or domain, not by file type (when appropriate for the language/framework).

57. Keep related code together. High cohesion, loose coupling.

58. Separate concerns: business logic, data access, presentation, configuration.

## API Design (When Applicable)

59. Follow REST principles or GraphQL best practices as appropriate.

60. Use proper HTTP methods and status codes.

61. Version APIs appropriately (URL versioning, header versioning, etc.).

62. Document APIs clearly (OpenAPI/Swagger, GraphQL schema, etc.).

## Data Handling

63. Validate data at boundaries (API inputs, database outputs, file parsing).

64. Use appropriate data structures for the task at hand.

65. Be explicit about data types. Use type systems when available.

66. Handle timezone-aware dates and times correctly. Store in UTC when possible.

## Code Portability

67. Avoid platform-specific code unless necessary. Abstract platform differences when possible.

68. Use cross-platform libraries when available.

69. Document any platform-specific requirements or behaviors.

---

## Quick Reference - Universal Standards

### Project Setup
- Create CHANGES.md
- Keep README.md updated
- Include config templates (.env.example, or local.settings.json.template for Azure projects)
- Use appropriate dependency management

### Code Quality
- Self-documenting names (follow language conventions)
- DRY: 3+ repetitions → function
- Functions <50 lines, max 4 params, max 3 nesting
- One responsibility per function
- Clean up unused code

### Comments & Documentation
- Comment WHY not WHAT
- Explain non-obvious decisions
- Document complex algorithms
- Use language-appropriate doc format (JSDoc, docstrings, etc.)

### Error Handling
- Proper error handling (try/catch, Result types, etc.)
- Validate inputs
- Never fail silently
- Handle edge cases (null, empty,