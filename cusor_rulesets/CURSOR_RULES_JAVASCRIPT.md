# Cursor AI Development Rules - JavaScript/TypeScript

These rules apply to ANY JavaScript or TypeScript project (frontend, backend, Node.js, Deno, Bun, etc.).

## Language Version & Syntax

1. Use ES14/ES2023 syntax: const/let (never var), arrow functions, destructuring, spread operator, template literals, async/await (not .then()), optional chaining (?.), nullish coalescing (??), Array.at(), Object.hasOwn().

2. Always use const by default. Use let only when reassignment is necessary. Never use var.

3. Use arrow functions as default. Use regular functions only when you need this binding or for generators.

4. Use template literals for string interpolation: \`Hello ${name}\` not "Hello " + name.

5. Use async/await instead of .then() chains for better readability and error handling.

6. Use optional chaining (?.) to safely access nested properties: user?.address?.street

7. Use nullish coalescing (??) for default values: const value = input ?? defaultValue (not input || defaultValue).

8. Use destructuring for objects and arrays: const { name, age } = user; const [first, ...rest] = array;

9. Use spread operator for copying and merging: const newObj = { ...oldObj, updated: true }

10. Use Array methods (map, filter, reduce, find, some, every) instead of for loops when appropriate.

## TypeScript

11. Use TypeScript for all projects when possible. TypeScript provides type safety, better IDE support, and catches errors early.

12. Never use "any" type unless absolutely necessary with documented justification. Use "unknown" if type is truly unknown.

13. Fix type errors immediately rather than working around them.

14. Do not ignore or suppress TypeScript errors (@ts-ignore, @ts-expect-error) — focus on clean, passing code.

15. Define TypeScript interfaces for all object parameters passed between functions.

16. Use union types appropriately: string | number, not any.

17. Use generics for reusable type-safe functions and components.

18. Use type guards to narrow types: if (typeof x === 'string'), Array.isArray(), etc.

19. Enable strict mode in tsconfig.json for maximum type safety.

20. Use discriminated unions for complex state management or variant types.

## Naming Conventions

21. camelCase for variables and functions: getUserById, totalAmount, isActive

22. PascalCase for classes, types, interfaces, and enums: User, UserProfile, PaymentStatus

23. SCREAMING_SNAKE_CASE for constants that are truly constant: API_BASE_URL, MAX_RETRY_COUNT

24. Prefix boolean variables with is, has, should, can: isLoading, hasPermission, shouldRender

25. Be descriptive: calculateUserAge() not calc(), getUserById() not getUser()

26. Use plural names for arrays/collections: users, transactions, errorMessages

## Functions

27. Keep functions small and focused (target <50 lines).

28. Functions should do one thing and do it well (Single Responsibility Principle).

29. Max 4 parameters. If you need more, use an options object.

30. Pure functions are preferred: same input always produces same output, no side effects.

31. Avoid side effects when possible. If a function has side effects, make it obvious in the name: updateUserInDatabase(), not user().

32. Use default parameters: function greet(name = 'Guest') {}

33. Use rest parameters for variable arguments: function sum(...numbers) {}

## Async/Await & Promises

34. Always use async/await instead of .then() chains for better readability.

35. Always handle errors with try/catch in async functions.

36. Never use async/await without error handling.

37. For parallel operations, use Promise.all() or Promise.allSettled(): await Promise.all([fetch1(), fetch2()])

38. Don't await unnecessarily in series when operations can run in parallel.

39. Use Promise.race() for timeouts or first-to-complete scenarios.

## Error Handling

40. Use try/catch blocks for async operations and code that might throw.

41. Create custom error classes for domain-specific errors.

42. Always provide meaningful error messages with context.

43. Log errors appropriately (console.error in dev, proper logging service in production).

44. Validate inputs at function boundaries. Use type guards or validation libraries (Zod, Yup, io-ts).

45. Handle edge cases: null, undefined, empty strings, empty arrays, NaN, Infinity.

## Objects & Arrays

46. Use object shorthand: { name, age } instead of { name: name, age: age }

47. Use computed property names when dynamic: { [key]: value }

48. Prefer immutability: return new objects/arrays rather than mutating existing ones.

49. Use Object.freeze() for truly immutable objects when needed.

50. For array operations, use map/filter/reduce instead of mutating methods like push/splice when possible.

51. Use Array.from() to convert array-like objects to arrays.

52. Use Set for unique values, Map for key-value pairs with non-string keys.

## Modules & Imports

53. Use ES modules (import/export) not CommonJS (require/module.exports) unless targeting old Node.js.

54. Prefer named exports over default exports for better refactoring and IDE support.

55. Use default exports only for main component/class of a module.

56. Group imports logically: external libraries first, then internal modules, then relative imports.

57. Use absolute imports when available (via path aliases) to avoid ../../../ hell.

58. Don't use wildcard imports (import * as foo) unless necessary.

## Code Organization

59. One class/component per file (with exceptions for tightly coupled utility classes).

60. Keep files focused and reasonably sized (<300-400 lines).

61. Extract reusable logic into utility functions/modules.

62. Use index files to re-export from a module, but don't overuse them.

## Performance

63. Avoid unnecessary object/array creation in loops or frequently called functions.

64. Use memoization for expensive calculations (useMemo, useCallback in React, or manual caching).

65. Prefer for loops over forEach/map for performance-critical code (rare).

66. Avoid memory leaks: clean up event listeners, clear timers, cancel subscriptions.

## Modern JavaScript Features to Use

67. Array.at() for accessing elements from the end: array.at(-1) for last element.

68. Object.hasOwn() instead of hasOwnProperty: Object.hasOwn(obj, 'prop')

69. Array.findLast() and Array.findLastIndex() when searching from the end.

70. String methods: includes(), startsWith(), endsWith(), trim(), trimStart(), trimEnd()

71. Object methods: Object.keys(), Object.values(), Object.entries(), Object.fromEntries()

72. Array methods: flat(), flatMap() for flattening arrays.

## Things to Avoid

73. Never use == or !=. Always use === or !==.

74. Don't use with statement (it's confusing and deprecated).

75. Avoid eval() (security risk and performance issue).

76. Don't modify built-in prototypes (Array.prototype, Object.prototype, etc.).

77. Avoid using arguments object. Use rest parameters instead: (...args)

78. Don't create functions inside loops (creates new function each iteration).

## JSON Handling

79. Always use try/catch when parsing JSON: try { JSON.parse(data) } catch {}

80. Validate JSON structure after parsing. Don't assume shape.

81. Use JSON.stringify() with proper null replacer and space arguments for debugging.

## Date & Time

82. Use modern date libraries (date-fns, Day.js, Temporal when widely available) instead of moment.js.

83. Always be aware of timezones. Store dates in UTC when possible.

84. Use ISO 8601 format for date strings: new Date().toISOString()

## Regular Expressions

85. Use literal notation for static patterns: /pattern/flags not new RegExp('pattern')

86. Use named capture groups for clarity: /(?<year>\d{4})-(?<month>\d{2})/

87. Test regex patterns thoroughly. They're easy to get wrong.

## Comments & Documentation

88.Use JSDoc comments for public functions:
```javascript
/**
 * Calculates the age based on birth date
 * @param {Date} birthDate - The date of birth
 * @returns {number} Age in years
 */
function calculateAge(birthDate) { ... }
```
89. Comment WHY, not WHAT. Code should be self-documenting.

90. Use TODO comments with assignee: // TODO(username): implement caching

## Testing

91. Write unit tests for business logic and utility functions.

92. Use testing libraries appropriate for the environment: Jest, Vitest, Node's test runner.

93. Test edge cases: null, undefined, empty strings, empty arrays, large numbers, negative numbers.

94. Mock external dependencies in tests (API calls, database, etc.).

## Debugging

95. Use debugger statement and browser/Node.js debugging tools, not just console.log.

96. Use console.table() for arrays of objects, console.dir() for deep object inspection.

97. Remove debug console statements before committing.

---

## Quick Reference - JavaScript/TypeScript

### ES14 Syntax
- const/let (never var)
- Arrow functions
- Template literals: \`Hello ${name}\`
- async/await (not .then())
- Optional chaining: user?.address?.street
- Nullish coalescing: value ?? default
- Destructuring: const { name } = user
- Spread: { ...obj, updated: true }

### TypeScript
- Always use TypeScript when possible
- Never "any" without justification
- Fix type errors immediately
- Define interfaces for object parameters
- Enable strict mode
- Use union types and generics

### Naming
- camelCase: getUserById, totalAmount
- PascalCase: User, UserProfile
- SCREAMING_SNAKE_CASE: API_BASE_URL
- Prefix booleans: isActive, hasPermission

### Functions
- Keep small (<50 lines)
- One responsibility
- Max 4 parameters (use options object)
- Prefer pure functions
- Use default parameters

### Async
- async/await (not .then())
- Always try/catch
- Promise.all() for parallel operations
- Handle errors meaningfully

### Error Handling
- try/catch for async and risky operations
- Custom error classes
- Meaningful error messages
- Validate inputs (Zod, Yup, type guards)
- Handle edge cases

### Objects & Arrays
- Object shorthand: { name, age }
- Prefer immutability
- Use map/filter/reduce
- Use Set for unique, Map for key-value

### Code Organization
- ES modules (import/export)
- Named exports preferred
- One class/component per file
- Files <300-400 lines

### Things to Avoid
- Never var, ==, with, eval()
- Don't modify built-in prototypes
- Don't use arguments (use ...args)
- No functions in loops