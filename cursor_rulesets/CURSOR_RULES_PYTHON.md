# Cursor AI Development Rules - Python/Data Science

## Project Structure & Documentation

1. For every project, create a CHANGES.md file that will track any major changes and features that we make.

2. Follow existing project structure and coding conventions.

3. Keep README.md updated: installation steps, dependencies (requirements.txt or pyproject.toml), how to run locally, environment setup.

4. Include a .env.example file showing required environment variables (without actual values). **Exception**: For Azure Functions projects, use `local.settings.json.template` instead (see CURSOR_RULES_AZURE.md).

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
- Include .env.example (or local.settings.json.template for Azure Functions)
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